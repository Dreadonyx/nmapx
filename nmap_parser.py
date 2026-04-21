"""
Parse nmap XML output into structured dicts.
"""

import xml.etree.ElementTree as ET
from typing import Optional

SEVERITY = {
    "open":     "high",
    "filtered": "medium",
    "closed":   "low",
}

SERVICE_COLORS = {
    "http": "#3b82f6", "https": "#3b82f6",
    "ssh":  "#f59e0b",
    "ftp":  "#f97316",
    "smtp": "#a78bfa",
    "dns":  "#22c55e",
    "smb":  "#ef4444", "microsoft-ds": "#ef4444",
    "rdp":  "#ef4444", "ms-wbt-server": "#ef4444",
    "mysql": "#06b6d4", "postgresql": "#06b6d4",
    "telnet": "#f97316",
}

def parse_xml(xml_str: str) -> dict:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        return {"error": str(e), "hosts": []}

    hosts = []
    for host in root.findall("host"):
        # status
        status_el = host.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"
        if status != "up":
            continue

        # addresses
        addrs = {}
        for addr in host.findall("address"):
            addrs[addr.get("addrtype")] = addr.get("addr")

        # hostnames
        names = []
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            names = [h.get("name") for h in hostnames_el.findall("hostname") if h.get("name")]

        # os detection
        os_name = None
        os_el = host.find("os")
        if os_el is not None:
            best = os_el.find("osmatch")
            if best is not None:
                os_name = f"{best.get('name')} ({best.get('accuracy')}%)"

        # ports
        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el  = port.find("state")
                service_el = port.find("service")
                script_els = port.findall("script")

                state   = state_el.get("state", "unknown") if state_el is not None else "unknown"
                portid  = int(port.get("portid", 0))
                proto   = port.get("protocol", "tcp")

                svc_name    = ""
                svc_product = ""
                svc_version = ""
                svc_extra   = ""
                if service_el is not None:
                    svc_name    = service_el.get("name", "")
                    svc_product = service_el.get("product", "")
                    svc_version = service_el.get("version", "")
                    svc_extra   = service_el.get("extrainfo", "")

                scripts = []
                for sc in script_els:
                    scripts.append({"id": sc.get("id"), "output": sc.get("output", "")})

                ports.append({
                    "port":     portid,
                    "proto":    proto,
                    "state":    state,
                    "service":  svc_name,
                    "product":  svc_product,
                    "version":  svc_version,
                    "extra":    svc_extra,
                    "scripts":  scripts,
                    "color":    SERVICE_COLORS.get(svc_name.lower(), "#6b7280"),
                    "severity": SEVERITY.get(state, "low"),
                })

        ports.sort(key=lambda p: p["port"])

        # timing
        times_el = host.find("times")
        rtt = None
        if times_el is not None:
            srtt = times_el.get("srtt")
            rtt  = f"{int(srtt)//1000} ms" if srtt else None

        hosts.append({
            "ip":        addrs.get("ipv4") or addrs.get("ipv6", "?"),
            "mac":       addrs.get("mac"),
            "hostnames": names,
            "os":        os_name,
            "status":    status,
            "rtt":       rtt,
            "ports":     ports,
            "open_count":     sum(1 for p in ports if p["state"] == "open"),
            "filtered_count": sum(1 for p in ports if p["state"] == "filtered"),
        })

    # scan stats
    runstats = root.find("runstats")
    stats = {}
    if runstats is not None:
        finished = runstats.find("finished")
        hosts_el = runstats.find("hosts")
        if finished is not None:
            stats["elapsed"] = finished.get("elapsed", "?") + "s"
            stats["summary"] = finished.get("summary", "")
        if hosts_el is not None:
            stats["up"]    = hosts_el.get("up", "0")
            stats["down"]  = hosts_el.get("down", "0")
            stats["total"] = hosts_el.get("total", "0")

    return {"hosts": hosts, "stats": stats}
