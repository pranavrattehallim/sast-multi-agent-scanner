# SAST Multi-Agent Security Scanner

**CSEC 594 — Security Capstone | DePaul University**
**By Pranav Rattehalli Mahesh (2215997)**

An AI-assisted Static Application Security Testing (SAST) system with a hosted web dashboard that triggers a local multi-agent scanning pipeline and delivers a downloadable PDF/Markdown report.

---

## What This Does

Upload a zipped code repository through the web dashboard. Three AI agents run sequentially on your local machine:

1. **Agent 1 (Scanner)** — Reads every supported source file, chunks large files, and asks DeepSeek to identify security vulnerabilities with file, line, severity, OWASP category, CWE, and evidence.
2. **Agent 2 (Critic)** — Re-checks each finding against surrounding code context. Confirms true positives, rejects false positives, adds confidence scores and verification notes.
3. **Agent 3 (Reporter)** — Converts verified findings into a structured PDF + Markdown report with executive summary, technical summary, and top remediation actions.

---

## Architecture

```
Browser (anywhere)
    ↓
Firebase Hosting — https://sast-scanner-capstone.web.app
    ↓  (API calls)
Cloudflare Tunnel — stable HTTPS URL → localhost:8000
    ↓
FastAPI — receives uploads, manages jobs, serves reports
    ↓
BASEwAGENTS.py — multi-agent pipeline
    ↓
Ollama + DeepSeek (deepseek-coder-v2:latest) — local LLM
```

**All compute runs on your local Mac. No code leaves your machine.**

---

## Tech Stack

### Backend
| Component | Purpose |
|-----------|---------|
| Python 3.11+ | Runtime |
| FastAPI + Uvicorn | Web server, REST API, background tasks |
| Ollama | Local LLM runtime |
| DeepSeek Coder v2 | The model used by all three agents |
| ReportLab | PDF generation |

### Frontend
| Component | Purpose |
|-----------|---------|
| React + TypeScript | UI framework |
| Vite 5 | Build tooling |
| Tailwind CSS v3 | Styling |
| shadcn/ui | UI components (Card, Button, Badge, Progress, Input, Label) |
| framer-motion | Animations |
| lucide-react | Icons |

### Infrastructure
| Service | Purpose | Cost |
|---------|---------|------|
| Firebase Hosting | Serves the static React frontend | Free |
| Cloudflare Tunnel | Exposes local backend to the internet | Free |
| Ollama (local) | Runs DeepSeek model on your Mac | Free |

---

## Project Structure

```
SASTWorkspace/
├── Backend/
│   ├── BASEwAGENTS.py        # Multi-agent pipeline (Scanner, Critic, Reporter)
│   └── main.py               # FastAPI server + job management
├── Frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── ScannerDashboard.tsx   # Main dashboard UI
│   │   │   └── ui/                    # shadcn components
│   │   ├── lib/utils.ts               # Tailwind utility
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── .env.production               # VITE_API_BASE (Cloudflare tunnel URL)
│   ├── vite.config.ts
│   └── package.json
```

### Workspace (auto-created on Mac at ~/sast-workspace/)
```
~/sast-workspace/
├── uploads/<job_id>/source.zip       # Deleted after scan
├── workspace/<job_id>/               # Extracted files — deleted after scan
├── outputs/<job_id>/
│   ├── final_report.pdf              # Served for download
│   ├── final_report.md
│   ├── raw_findings.json
│   ├── verified_findings.json
│   ├── rejected_findings.json
│   ├── run_metadata.json
│   └── report_summary.json
└── jobs/<job_id>/status.json         # Polled by frontend every 2 seconds
```

---

## Supported Languages

`.py` `.js` `.ts` `.jsx` `.tsx` `.go` `.rs` `.java` `.kt` `.c` `.cpp` `.h` `.cs` `.php` `.rb` `.swift` `.yaml` `.yml` `.env` `.sh` `.bash`

---

## Prerequisites

- macOS (Apple Silicon or Intel)
- Python 3.11+
- Node.js 18+
- [Ollama](https://ollama.com) installed
- DeepSeek Coder v2 pulled: `ollama pull deepseek-coder-v2:latest`
- [Cloudflare](https://cloudflare.com) free account
- [Firebase](https://firebase.google.com) free account

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/sast-scanner.git
cd sast-scanner
```

### 2. Install backend dependencies

```bash
cd Backend
pip3 install fastapi uvicorn python-multipart ollama reportlab
```

### 3. Install frontend dependencies

```bash
cd Frontend
npm install
```

### 4. Install Cloudflare tunnel

```bash
brew install cloudflared
```

---

## Running the System

You need three terminals open every session.

### Terminal 1 — Ollama
```bash
ollama serve
```

### Terminal 2 — FastAPI backend
```bash
cd Backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Terminal 3 — Cloudflare tunnel
```bash
cloudflared tunnel --url http://localhost:8000
```

Copy the printed URL (e.g. `https://random-words.trycloudflare.com`).

### Update frontend with new tunnel URL
```bash
cd Frontend
echo 'VITE_API_BASE=https://random-words.trycloudflare.com' > .env.production
npm run build && firebase deploy
```

> **Note:** The Cloudflare tunnel URL changes every time you restart it. You need to rebuild and redeploy the frontend each session. To avoid this — set up a named Cloudflare tunnel with a permanent URL.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans` | Upload ZIP, start scan job. Returns `job_id` |
| `GET` | `/api/scans/{job_id}/status` | Returns status, progress, stage, file counts |
| `GET` | `/api/scans/{job_id}/report` | Download final PDF report |

### Status Response Schema
```json
{
  "job_id": "uuid",
  "status": "queued | scanning | completed | failed",
  "stage": "current stage description",
  "progress": 0-100,
  "files_scanned": 12,
  "total_files": 15,
  "report_ready": true,
  "error": null
}
```

---

## How BASEwAGENTS.py Works

### Key Configuration
```python
DEFAULT_MODEL = "deepseek-coder-v2:latest"
MAX_CHARS_PER_CHUNK = 30000       # Files larger than this get chunked
CONTEXT_WINDOW_LINES = 25         # Lines of context passed to Agent 2
```

### Agent 1 — Scanner
- Walks the repository, skips excluded dirs (`node_modules`, `.git`, `__pycache__`, `__MACOSX`, etc.)
- Chunks files larger than 30,000 chars, preserving absolute line numbers
- Sends each chunk to DeepSeek with a SAST-focused system prompt
- Returns findings with: title, severity, OWASP, CWE, line, evidence snippet, description, attack path, recommendation

### Agent 2 — Critic
- Takes each raw finding and extracts ±25 lines of surrounding context
- Re-evaluates against local code — checks for sanitization, guards, dead code
- Returns verdict (confirmed/rejected), updated confidence, preconditions, verification notes
- Aggressively rejects false positives

### Agent 3 — Reporter
- Receives all verified findings and run metadata
- Generates executive summary (non-technical), technical summary, and top 5 actions
- Outputs both Markdown and PDF via ReportLab

### Finding Schema
```json
{
  "id": "path/to/file.py::1",
  "file": "relative/path.py",
  "language": "Python",
  "title": "SQL Injection via string interpolation",
  "severity": "Critical | High | Medium | Low | Informational",
  "owasp": "A01:2021 - Injection",
  "cwe": "CWE-89",
  "line": 42,
  "end_line": 44,
  "confidence": "high | medium | low",
  "evidence_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
  "description": "...",
  "attack_path": "...",
  "recommendation": "..."
}
```

---

## Evaluation Metrics (per Proposal)

| Metric | Description |
|--------|-------------|
| Precision | % of reported findings confirmed as true positives |
| Recall | % of known issues identified by the system |
| Triage effectiveness | Reduction in findings after Agent 2 vs Agent 1 |
| Evidence quality | File + line accuracy, snippet relevance, reasoning coherence |
| Coverage | % of eligible files and functions processed |
| Repeatability | Output stability across identical runs |
| Runtime | Total scan time per repo and per KLOC |

---

## Limitations

- SAST only — no DAST, fuzzing, or runtime execution
- Results are decision-support, not definitive vulnerability proof
- Tunnel URL changes each session (see note above)
- No authentication on dashboard (intentional — prototype scope)
- Analysis quality constrained by context window and missing build/runtime config
- Larger repos may hit token/time caps

---

## Vulnerability Categories Covered

| OWASP | Category |
|-------|----------|
| A01 | Injection (SQL, Command, LDAP, XPath, Template/SSTI) |
| A02 | Broken Authentication & Session Management |
| A03 | Sensitive Data Exposure (Hardcoded Secrets, Weak Crypto) |
| A04 | XML External Entities (XXE) |
| A05 | Broken Access Control (Path Traversal, IDOR) |
| A06 | Security Misconfiguration (Debug mode, CORS, Missing headers) |
| A07 | Cross-Site Scripting (Reflected, Stored) |
| A08 | Insecure Deserialization (Pickle, YAML, Marshal) |
| A09 | Using Components with Known Vulnerabilities |
| A10 | Insufficient Logging & Monitoring |
| Extra | SSRF, Open Redirect, Weak Randomness, Race Conditions, eval/exec injection |

---

## License

For academic/research use only. Do not deploy the benchmark vulnerable code (`vulnerable_benchmark.py`) in any real environment.
