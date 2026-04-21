"""
NmapX — FastAPI backend
WebSocket streams live nmap output, parses XML, Groq AI threat analysis.
"""

import os, asyncio, subprocess, tempfile, json, re
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from groq import Groq
import nmap_parser

load_dotenv()

app = FastAPI(title="NmapX")
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

GROQ_KEY    = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_KEY) if GROQ_KEY else None

SCAN_PROFILES = {
    "fast":    {"flags": ["-T4", "-F"],                          "label": "Fast Scan"},
    "full":    {"flags": ["-T4", "-A", "-p-"],                   "label": "Full Port Scan"},
    "stealth": {"flags": ["-sS", "-T2", "-p-"],                  "label": "Stealth SYN Scan"},
    "udp":     {"flags": ["-sU", "--top-ports", "200"],          "label": "UDP Scan"},
    "vuln":    {"flags": ["-sV", "--script=vuln", "-T4"],        "label": "Vuln Scan"},
    "ping":    {"flags": ["-sn"],                                 "label": "Ping Sweep"},
    "version": {"flags": ["-sV", "-T4", "--version-intensity=8"],"label": "Version Detection"},
    "custom":  {"flags": [],                                      "label": "Custom"},
}


class AnalyzeRequest(BaseModel):
    scan_result: dict


@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.get("/profiles")
def profiles():
    return {k: v["label"] for k, v in SCAN_PROFILES.items()}


@app.websocket("/ws/scan")
async def scan_ws(websocket: WebSocket):
    await websocket.accept()

    try:
        data = await websocket.receive_json()
        target      = data.get("target", "").strip()
        profile     = data.get("profile", "fast")
        custom_flags = data.get("custom_flags", "").strip()

        if not target:
            await websocket.send_json({"type": "error", "msg": "No target specified."})
            return

        # basic target sanity — allow IPs, ranges, hostnames, CIDR
        if not re.match(r'^[a-zA-Z0-9._/\-: ,]+$', target):
            await websocket.send_json({"type": "error", "msg": "Invalid target."})
            return

        flags = list(SCAN_PROFILES.get(profile, SCAN_PROFILES["fast"])["flags"])
        if profile == "custom" and custom_flags:
            BLOCKED_FLAGS = {'-oN', '-oX', '-oG', '-oA', '-oS', '--script', '-iL', '--excludefile', '--datadir', '--resume'}
            user_flags = custom_flags.split()
            for f in user_flags:
                if f in BLOCKED_FLAGS or any(f.startswith(b + '=') for b in BLOCKED_FLAGS):
                    await websocket.send_json({"type": "error", "msg": f"Flag '{f}' is not allowed."})
                    return
            flags = user_flags

        # XML output file
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            xml_path = tf.name

        cmd = ["nmap"] + flags + ["-oX", xml_path, "--stats-every", "3s"] + target.split(",")
        await websocket.send_json({"type": "start", "cmd": " ".join(cmd)})

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        # stream output line by line
        async for line in proc.stdout:
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                await websocket.send_json({"type": "output", "line": text})

        await proc.wait()

        # parse XML
        try:
            with open(xml_path) as f:
                xml_str = f.read()
            result = nmap_parser.parse_xml(xml_str)
        except Exception as e:
            result = {"hosts": [], "stats": {}, "parse_error": str(e)}
        finally:
            os.unlink(xml_path)

        await websocket.send_json({"type": "done", "result": result})

    except WebSocketDisconnect:
        try:
            proc.terminate()
        except Exception:
            pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "msg": str(e)})
        except: pass


@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    if not groq_client:
        raise HTTPException(503, "Groq API key not configured.")

    result = req.scan_result
    hosts  = result.get("hosts", [])

    if not hosts:
        return JSONResponse({"analysis": "No hosts found in scan results."})

    # build compact summary for LLM
    summary_lines = []
    for h in hosts:
        line = f"Host: {h['ip']}"
        if h.get("hostnames"):
            line += f" ({', '.join(h['hostnames'])})"
        if h.get("os"):
            line += f" | OS: {h['os']}"
        for p in h["ports"]:
            svc = p["service"]
            if p.get("product"): svc += f" {p['product']}"
            if p.get("version"): svc += f" {p['version']}"
            line += f"\n  {p['port']}/{p['proto']} {p['state']} — {svc}"
            for sc in p.get("scripts", []):
                line += f"\n    [{sc['id']}] {sc['output'][:200]}"
        summary_lines.append(line)

    summary = "\n\n".join(summary_lines)

    resp = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": (
                "You are a senior penetration tester and security analyst. "
                "Analyze the nmap scan results and provide a concise threat assessment. "
                "For each host: identify risky open ports, outdated services, potential CVEs, "
                "attack vectors, and prioritized recommendations. "
                "Use markdown with headers per host. Be specific, technical, and actionable. "
                "Keep total response under 600 words."
            )},
            {"role": "user", "content": f"Nmap scan results:\n\n{summary}"},
        ],
        max_tokens=800,
        temperature=0.3,
    )

    return JSONResponse({"analysis": resp.choices[0].message.content})
