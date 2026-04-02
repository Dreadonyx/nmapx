# nmapx 🔍

> A clean web UI for Nmap — live output streaming + Groq AI threat analysis.

Nmap output in the terminal gets messy fast. nmapx streams it live to a browser UI, parses the results into a readable format, and runs them through Groq AI for a threat assessment.

## Scan profiles

| Profile | Description |
|---|---|
| Fast | Quick host discovery |
| Full Port | All 65535 ports |
| Stealth SYN | Half-open scan |
| UDP | UDP port scan |
| Vuln Script | NSE vulnerability scripts |
| Ping Sweep | Live host detection |
| Version Detection | Service version fingerprinting |
| Custom | Your own flags |

## Setup

> Requires Nmap installed on the system.

```bash
git clone https://github.com/Dreadonyx/nmapx
cd nmapx
pip install -r requirements.txt
cp .env.example .env
# add your Groq API key
python main.py
```

Open `http://localhost:8000`.

## Stack

- Python / FastAPI
- WebSockets (live output streaming)
- Groq API (threat analysis)
- Nmap (subprocess)
- Vanilla HTML/CSS/JS

---

**Only scan systems you own or have permission to scan.**
