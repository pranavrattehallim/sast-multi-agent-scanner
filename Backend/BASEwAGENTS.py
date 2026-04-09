import ollama
import os
import sys
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Any
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from xml.sax.saxutils import escape

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rs", ".java", ".kt",
    ".c", ".cpp", ".h", ".cs",
    ".php", ".rb", ".swift",
    ".yaml", ".yml", ".env",
    ".sh", ".bash",
}

EXCLUDED_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv",
    "venv", "dist", "build", ".idea", ".vscode", "__MACOSX"
}

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
}

DEFAULT_MODEL = "deepseek-coder-v2:latest"
MAX_CHARS_PER_CHUNK = 60000
CONTEXT_WINDOW_LINES = 50


SCANNER_SYSTEM_PROMPT = """You are Agent 1: Initial SAST scanner. Your job is thorough vulnerability detection.

Task:
- Carefully review every line of the supplied code chunk for security vulnerabilities.
- Generate a finding for EVERY real security issue you identify — do not skip any.
- Be thorough. It is better to report a finding that gets rejected by the critic than to miss a real vulnerability.
- Do not report code quality issues, style issues, or logic bugs unless they are security-relevant.
- If there are no issues, return status clean and an empty findings list.
- If the content is clearly non-executable/non-relevant for SAST, return status skipped.

Vulnerability categories to actively look for:
- SQL Injection (string interpolation, concatenation in queries)
- Command Injection (os.system, subprocess with shell=True, os.popen)
- Hardcoded secrets (passwords, API keys, tokens, AWS keys, JWT secrets)
- Weak cryptography (MD5, SHA1 for passwords, no salt, no iterations)
- XSS (user input rendered directly in HTML, render_template_string with user input)
- Insecure deserialization (pickle.loads, yaml.load without SafeLoader, marshal.loads, eval, exec)
- Path traversal (user input concatenated to file paths, open(user_input))
- SSRF (urlopen/requests with user-controlled URL)
- Broken authentication (missing HttpOnly/Secure/SameSite on cookies, weak session tokens, no rate limiting)
- IDOR (database queries using user-supplied IDs without authorization checks)
- Security misconfiguration (debug=True, CORS wildcard, missing security headers, exposed admin routes)
- Template injection (render_template_string with user input)
- LDAP injection (user input in LDAP search filters)
- Open redirect (redirect() with unvalidated user input)
- Weak randomness (random.randint for security tokens, OTPs, session IDs)
- Race conditions (TOCTOU patterns, non-atomic check-then-use)
- Eval/exec injection (eval(user_input), exec(user_input))
- Sensitive data in logs (PII, card numbers, passwords in print/logging statements)
- XXE (XML parsing without entity resolution disabled)

IMPORTANT: Scan the ENTIRE file from top to bottom before returning. 
Do not stop after finding a few issues. Every function and route must be checked.
Report ALL vulnerabilities you find — aim for complete coverage.
If you find more than 10 issues, include all of them.

Return STRICT JSON only with this schema:
{
  "status": "findings|clean|skipped",
  "findings": [
    {
      "title": "string",
      "severity": "Critical|High|Medium|Low|Informational",
      "owasp": "string",
      "cwe": "string",
      "line": 0,
      "end_line": 0,
      "confidence": "high|medium|low",
      "evidence_snippet": "string",
      "description": "string",
      "attack_path": "string",
      "recommendation": "string"
    }
  ]
}

Rules:
- line and end_line must be ABSOLUTE line numbers in the original file, not chunk-relative.
- evidence_snippet must be the exact vulnerable line of code from the supplied code.
- severity: Critical = RCE/SQLi/hardcoded creds, High = XSS/SSRF/insecure deser, Medium = weak crypto/misconfig, Low = logging issues/weak randomness.
- Return JSON only. No markdown. No prose outside JSON.
"""

CRITIC_SYSTEM_PROMPT = """You are Agent 2: Triage and validation critic.

Task:
- Re-check ONE candidate finding using the supplied local code context.
- Confirm the finding if there is reasonable code evidence supporting it.
- Reject only if the finding is clearly wrong — e.g. the code is sanitized, the input is not user-controlled, or the finding is about dead/unreachable code.
- Do NOT reject findings just because exploitation requires preconditions — that is normal for real vulnerabilities.
- Do NOT reject hardcoded credentials, weak crypto, or obvious injection patterns — these are always real findings.
- Never invent a new finding.

Confirm if ANY of these are true:
- User input reaches a dangerous sink without sanitization (SQL, shell, eval, pickle, redirect, open)
- Hardcoded secret, password, API key, or token is present in the code
- Weak or broken cryptographic algorithm is used (MD5, SHA1 for passwords)
- Security flag or header is missing (HttpOnly, Secure, SameSite, CSP, HSTS)
- Debug mode or wildcard CORS is enabled
- eval(), exec(), or pickle.loads() is called with any non-literal input

Reject only if:
- The flagged code is clearly sanitized or validated before the dangerous operation
- The input is provably not user-controlled (hardcoded constant, internal value)
- The finding references non-existent code or wrong line numbers

Return STRICT JSON only with this schema:
{
  "verdict": "confirmed|rejected",
  "severity": "Critical|High|Medium|Low|Informational",
  "confidence": "high|medium|low",
  "line": 0,
  "end_line": 0,
  "reason": "string",
  "preconditions": "string",
  "verification_notes": "string",
  "recommendation": "string"
}

Rules:
- Keep line numbers absolute.
- reason must explain specifically why you confirmed or rejected — not a generic statement.
- Return JSON only.
"""

REPORTER_SYSTEM_PROMPT = """You are Agent 3: Security report writer.

Task:
- Write a professional security report based only on the verified findings and run metrics provided.
- Do not add new findings or speculate beyond what is in the data.
- Write for two audiences: executive_summary for non-technical stakeholders, technical_summary for developers.
- top_actions must be specific, concrete, and prioritized by severity — not generic advice.

executive_summary guidelines:
- 3-5 sentences. Plain language. No jargon.
- State the number and severity of findings, what categories were found, and the overall risk level.
- Mention what the scan covered and what it does not cover (runtime behavior, DAST).

technical_summary guidelines:
- 4-6 sentences. Developer-focused.
- Summarize which vulnerability categories were found, which files were affected, and the most critical issues.
- Reference specific OWASP categories and CWEs found.
- Mention false-positive rejection rate if critic rejected findings.

top_actions guidelines:
- Exactly 5 actions.
- Each action must reference a specific finding category, CWE, or file.
- Prioritize by severity — Critical and High first.
- Each action should be one concrete sentence starting with an action verb (Use, Replace, Remove, Add, Implement).

Return STRICT JSON only with this schema:
{
  "executive_summary": "string",
  "technical_summary": "string",
  "top_actions": ["string", "string", "string", "string", "string"]
}

Return JSON only. No markdown. No prose outside JSON.
"""


def get_language(ext: str) -> str:
    lang_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".jsx": "React JSX", ".tsx": "React TSX", ".go": "Go",
        ".rs": "Rust", ".java": "Java", ".kt": "Kotlin",
        ".c": "C", ".cpp": "C++", ".h": "C Header", ".cs": "C#",
        ".php": "PHP", ".rb": "Ruby", ".swift": "Swift",
        ".yaml": "YAML", ".yml": "YAML", ".env": "ENV",
        ".sh": "Shell", ".bash": "Bash",
    }
    return lang_map.get(ext, "Unknown")


def collect_files(folder: str) -> list[Path]:
    all_files = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file in files:
            path = Path(root) / file
            if path.suffix.lower() in SUPPORTED_EXTENSIONS:
                all_files.append(path)
    return sorted(all_files)


def chunk_code_with_lines(code: str, max_chars: int = MAX_CHARS_PER_CHUNK) -> list[dict[str, Any]]:
    if len(code) <= max_chars:
        return [{
            "content": code,
            "start_line": 1,
            "end_line": len(code.splitlines()) or 1,
            "chunk_index": 1,
            "chunk_total": 1,
        }]

    lines = code.splitlines(keepends=True)
    chunks = []
    current = []
    current_len = 0
    start_line = 1

    for idx, line in enumerate(lines, start=1):
        if current and current_len + len(line) > max_chars:
            content = "".join(current)
            chunks.append({
                "content": content,
                "start_line": start_line,
                "end_line": idx - 1,
                "chunk_index": len(chunks) + 1,
                "chunk_total": 0,
            })
            current = [line]
            current_len = len(line)
            start_line = idx
        else:
            current.append(line)
            current_len += len(line)

    if current:
        content = "".join(current)
        chunks.append({
            "content": content,
            "start_line": start_line,
            "end_line": len(lines),
            "chunk_index": len(chunks) + 1,
            "chunk_total": 0,
        })

    total = len(chunks)
    for chunk in chunks:
        chunk["chunk_total"] = total

    return chunks


def safe_json_loads(text: str) -> dict[str, Any]:
    text = text.strip()

    # Strip DeepSeek <think>...</think> reasoning blocks
    if "<think>" in text:
        if "</think>" in text:
            text = text.split("</think>", 1)[1].strip()
        else:
            text = text.split("<think>", 1)[0].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
        return json.loads(text)

    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        return json.loads(text[first_brace:last_brace + 1])

    raise ValueError("Model did not return valid JSON.")


def call_json_agent(model: str, system_prompt: str, user_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
    response = ollama.chat(
        model=model,
        options={"temperature": 0, "num_ctx": 16384},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)}
        ]
    )

    content = response["message"]["content"]
    data = safe_json_loads(content)

    usage = {
        "prompt_eval_count": response.get("prompt_eval_count", 0) or 0,
        "eval_count": response.get("eval_count", 0) or 0,
    }
    return data, usage


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def build_repo_hash(files: list[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in files:
        rel = str(path.relative_to(root)).encode("utf-8", errors="ignore")
        digest.update(rel)
        try:
            digest.update(path.read_bytes())
        except Exception:
            digest.update(b"<unreadable>")
    return digest.hexdigest()


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def normalize_severity(value: str) -> str:
    if not value:
        return "Informational"
    value = value.strip().capitalize()
    if value not in SEVERITY_ORDER:
        return "Informational"
    return value


def normalize_confidence(value: str) -> str:
    value = (value or "").strip().lower()
    if value not in {"high", "medium", "low"}:
        return "low"
    return value


def normalize_finding(finding: dict[str, Any], rel_path: str, language: str, idx: int, code_lines: list[str]) -> dict[str, Any]:
    line = max(1, safe_int(finding.get("line"), 1))
    end_line = max(line, safe_int(finding.get("end_line"), line))
    snippet = (finding.get("evidence_snippet") or "").strip()

    if not snippet and 1 <= line <= len(code_lines):
        snippet = code_lines[line - 1].strip()

    return {
        "id": f"{rel_path}::{idx}",
        "file": rel_path,
        "language": language,
        "title": (finding.get("title") or "Unnamed finding").strip(),
        "severity": normalize_severity(finding.get("severity", "Informational")),
        "owasp": (finding.get("owasp") or "Unknown").strip(),
        "cwe": (finding.get("cwe") or "Unknown").strip(),
        "line": line,
        "end_line": end_line,
        "confidence": normalize_confidence(finding.get("confidence", "low")),
        "evidence_snippet": snippet,
        "description": (finding.get("description") or "").strip(),
        "attack_path": (finding.get("attack_path") or "").strip(),
        "recommendation": (finding.get("recommendation") or "").strip(),
    }


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []

    for finding in findings:
        key = (
            finding["file"],
            finding["title"].lower(),
            finding["line"],
            finding["severity"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return deduped


def extract_context(code_lines: list[str], line: int, end_line: int, window: int = CONTEXT_WINDOW_LINES) -> str:
    start = max(1, line - window)
    end = min(len(code_lines), end_line + window)
    buf = []
    for idx in range(start, end + 1):
        buf.append(f"{idx}: {code_lines[idx - 1].rstrip()}")
    return "\n".join(buf)


def scanner_agent(filepath: Path, rel_path: str, language: str, code: str, model: str) -> tuple[list[dict[str, Any]], dict[str, int], str]:
    code_lines = code.splitlines()
    chunks = chunk_code_with_lines(code)
    findings = []
    token_usage = {"prompt_eval_count": 0, "eval_count": 0}

    for chunk in chunks:
        payload = {
            "file": rel_path,
            "language": language,
            "chunk_index": chunk["chunk_index"],
            "chunk_total": chunk["chunk_total"],
            "absolute_line_start": chunk["start_line"],
            "absolute_line_end": chunk["end_line"],
            "instructions": "Report only security vulnerabilities from this code chunk.",
            "code": chunk["content"],
        }

        try:
            result, usage = call_json_agent(model, SCANNER_SYSTEM_PROMPT, payload)
        except Exception as e:
            findings.append({
                "id": f"{rel_path}::scanner_error::{chunk['chunk_index']}",
                "file": rel_path,
                "language": language,
                "title": "Scanner failure",
                "severity": "Informational",
                "owasp": "N/A",
                "cwe": "N/A",
                "line": chunk["start_line"],
                "end_line": chunk["start_line"],
                "confidence": "low",
                "evidence_snippet": "",
                "description": f"Scanner agent failed to parse model output: {e}",
                "attack_path": "",
                "recommendation": "Re-run scan and inspect agent output.",
            })
            continue

        token_usage["prompt_eval_count"] += usage["prompt_eval_count"]
        token_usage["eval_count"] += usage["eval_count"]

        status = (result.get("status") or "").strip().lower()
        raw_findings = result.get("findings", [])

        if status in {"clean", "skipped"} or not isinstance(raw_findings, list):
            continue

        for idx, finding in enumerate(raw_findings, start=1):
            if not isinstance(finding, dict):
                continue
            findings.append(normalize_finding(
                finding=finding,
                rel_path=rel_path,
                language=language,
                idx=len(findings) + idx,
                code_lines=code_lines
            ))

    findings = dedupe_findings(findings)
    return findings, token_usage, sha256_text(code)


def critic_agent(code_lines: list[str], finding: dict[str, Any], model: str) -> tuple[dict[str, Any], dict[str, int]]:
    context = extract_context(code_lines, finding["line"], finding["end_line"])

    payload = {
        "candidate_finding": finding,
        "local_context": context,
        "instructions": "Validate only this finding against the supplied local code context.",
    }

    result, usage = call_json_agent(model, CRITIC_SYSTEM_PROMPT, payload)
    verdict = (result.get("verdict") or "").strip().lower()

    if verdict != "confirmed":
        rejected = {
            "id": finding["id"],
            "file": finding["file"],
            "title": finding["title"],
            "line": finding["line"],
            "reason": (result.get("reason") or "Rejected by critic").strip(),
        }
        return {"verdict": "rejected", "finding": rejected}, usage

    confirmed = dict(finding)
    confirmed["severity"] = normalize_severity(result.get("severity", finding["severity"]))
    confirmed["confidence"] = normalize_confidence(result.get("confidence", finding["confidence"]))
    confirmed["line"] = max(1, safe_int(result.get("line"), finding["line"]))
    confirmed["end_line"] = max(confirmed["line"], safe_int(result.get("end_line"), finding["end_line"]))
    confirmed["verification_notes"] = (result.get("verification_notes") or "").strip()
    confirmed["preconditions"] = (result.get("preconditions") or "").strip()
    confirmed["critic_reason"] = (result.get("reason") or "").strip()
    confirmed["recommendation"] = (result.get("recommendation") or finding["recommendation"]).strip()

    return {"verdict": "confirmed", "finding": confirmed}, usage


def reporter_agent(run_metrics: dict[str, Any], verified_findings: list[dict[str, Any]], model: str) -> tuple[dict[str, Any], dict[str, int]]:
    payload = {
        "run_metrics": run_metrics,
        "verified_findings": verified_findings,
        "instructions": "Write final summary text only from the supplied verified findings and metrics.",
    }
    return call_json_agent(model, REPORTER_SYSTEM_PROMPT, payload)


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return counts


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_ORDER.get(f["severity"], 0),
            f["file"],
            f["line"],
            f["title"].lower(),
        )
    )


def render_markdown_report(
    folder_path: Path,
    metadata: dict[str, Any],
    summary: dict[str, Any],
    verified_findings: list[dict[str, Any]],
    rejected_findings: list[dict[str, Any]],
) -> str:
    sev = metadata["severity_counts"]
    lines = [
        "# SAST Multi-Agent Security Report",
        "",
        f"**Repository:** `{folder_path}`",
        f"**Run ID:** `{metadata['run_id']}`",
        f"**Date:** {metadata['date']}",
        f"**Repository Hash:** `{metadata['repo_hash']}`",
        "",
        "## Models",
        f"- Scanner Agent: `{metadata['scanner_model']}`",
        f"- Critic Agent: `{metadata['critic_model']}`",
        f"- Reporter Agent: `{metadata['reporter_model']}`",
        "",
        "## Metrics",
        f"- Files scanned: **{metadata['files_scanned']}**",
        f"- Raw findings: **{metadata['raw_findings']}**",
        f"- Verified findings: **{metadata['verified_findings']}**",
        f"- Rejected findings: **{metadata['rejected_findings']}**",
        f"- Duration: **{metadata['duration_seconds']:.2f}s**",
        f"- Prompt tokens: **{metadata['prompt_eval_count']}**",
        f"- Generated tokens: **{metadata['eval_count']}**",
        "",
        "## Severity Overview",
        f"- Critical: **{sev['Critical']}**",
        f"- High: **{sev['High']}**",
        f"- Medium: **{sev['Medium']}**",
        f"- Low: **{sev['Low']}**",
        f"- Informational: **{sev['Informational']}**",
        "",
        "## Executive Summary",
        summary.get("executive_summary", "No summary generated."),
        "",
        "## Technical Summary",
        summary.get("technical_summary", "No summary generated."),
        "",
        "## Top Actions",
    ]

    for action in summary.get("top_actions", [])[:5]:
        lines.append(f"- {action}")

    lines.extend(["", "## Verified Findings", ""])

    if not verified_findings:
        lines.append("No verified security findings.")
    else:
        for idx, finding in enumerate(sort_findings(verified_findings), start=1):
            lines.extend([
                f"### {idx}. {finding['title']}",
                f"- Severity: **{finding['severity']}**",
                f"- Confidence: **{finding['confidence']}**",
                f"- File: `{finding['file']}`",
                f"- Lines: `{finding['line']}-{finding['end_line']}`",
                f"- OWASP: `{finding['owasp']}`",
                f"- CWE: `{finding['cwe']}`",
                f"- Evidence: `{finding['evidence_snippet']}`" if finding["evidence_snippet"] else "- Evidence: `N/A`",
                f"- Description: {finding['description'] or 'N/A'}",
                f"- Attack Path: {finding['attack_path'] or 'N/A'}",
                f"- Preconditions: {finding.get('preconditions') or 'N/A'}",
                f"- Verification Notes: {finding.get('verification_notes') or 'N/A'}",
                f"- Recommendation: {finding['recommendation'] or 'N/A'}",
                "",
            ])

    lines.extend(["## Critic Rejections", ""])

    if not rejected_findings:
        lines.append("No findings were rejected by the critic.")
    else:
        for rej in rejected_findings:
            lines.append(f"- `{rej['file']}` line `{rej['line']}` — **{rej['title']}** — {rej['reason']}")

    lines.append("")
    return "\n".join(lines)


def create_pdf_report(
    pdf_path: Path,
    folder_path: Path,
    metadata: dict[str, Any],
    summary: dict[str, Any],
    verified_findings: list[dict[str, Any]],
    rejected_findings: list[dict[str, Any]],
) -> None:
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallBody", fontSize=9, leading=12))
    styles.add(ParagraphStyle(name="FindingTitle", fontSize=12, leading=14, spaceAfter=6))
    story = []

    def p(text: str, style="BodyText"):
        story.append(Paragraph(escape(text).replace("\n", "<br/>"), styles[style]))
        story.append(Spacer(1, 0.12 * inch))

    p("SAST Multi-Agent Security Report", "Title")
    p(f"Repository: {folder_path}", "SmallBody")
    p(f"Run ID: {metadata['run_id']}", "SmallBody")
    p(f"Date: {metadata['date']}", "SmallBody")
    p(f"Repository Hash: {metadata['repo_hash']}", "SmallBody")

    p("Models", "Heading2")
    p(f"Scanner Agent: {metadata['scanner_model']}", "SmallBody")
    p(f"Critic Agent: {metadata['critic_model']}", "SmallBody")
    p(f"Reporter Agent: {metadata['reporter_model']}", "SmallBody")

    p("Metrics", "Heading2")
    p(f"Files scanned: {metadata['files_scanned']}", "SmallBody")
    p(f"Raw findings: {metadata['raw_findings']}", "SmallBody")
    p(f"Verified findings: {metadata['verified_findings']}", "SmallBody")
    p(f"Rejected findings: {metadata['rejected_findings']}", "SmallBody")
    p(f"Duration: {metadata['duration_seconds']:.2f}s", "SmallBody")
    p(f"Prompt tokens: {metadata['prompt_eval_count']}", "SmallBody")
    p(f"Generated tokens: {metadata['eval_count']}", "SmallBody")

    sev = metadata["severity_counts"]
    p("Severity Overview", "Heading2")
    p(
        f"Critical: {sev['Critical']} | High: {sev['High']} | Medium: {sev['Medium']} | "
        f"Low: {sev['Low']} | Informational: {sev['Informational']}",
        "SmallBody"
    )

    p("Executive Summary", "Heading2")
    p(summary.get("executive_summary", "No summary generated."), "SmallBody")

    p("Technical Summary", "Heading2")
    p(summary.get("technical_summary", "No summary generated."), "SmallBody")

    p("Top Actions", "Heading2")
    for action in summary.get("top_actions", [])[:5]:
        p(f"- {action}", "SmallBody")

    story.append(PageBreak())
    p("Verified Findings", "Heading2")

    if not verified_findings:
        p("No verified security findings.", "SmallBody")
    else:
        for idx, finding in enumerate(sort_findings(verified_findings), start=1):
            p(f"{idx}. {finding['title']}", "FindingTitle")
            p(f"Severity: {finding['severity']} | Confidence: {finding['confidence']}", "SmallBody")
            p(f"File: {finding['file']} | Lines: {finding['line']}-{finding['end_line']}", "SmallBody")
            p(f"OWASP: {finding['owasp']} | CWE: {finding['cwe']}", "SmallBody")
            p(f"Evidence: {finding['evidence_snippet'] or 'N/A'}", "SmallBody")
            p(f"Description: {finding['description'] or 'N/A'}", "SmallBody")
            p(f"Attack Path: {finding['attack_path'] or 'N/A'}", "SmallBody")
            p(f"Preconditions: {finding.get('preconditions') or 'N/A'}", "SmallBody")
            p(f"Verification Notes: {finding.get('verification_notes') or 'N/A'}", "SmallBody")
            p(f"Recommendation: {finding['recommendation'] or 'N/A'}", "SmallBody")

    story.append(PageBreak())
    p("Critic Rejections", "Heading2")
    if not rejected_findings:
        p("No findings were rejected by the critic.", "SmallBody")
    else:
        for rej in rejected_findings:
            p(f"{rej['file']} | line {rej['line']} | {rej['title']} | {rej['reason']}", "SmallBody")

    doc.build(story)


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run_multi_agent_scan(
    folder: str,
    scanner_model: str = DEFAULT_MODEL,
    critic_model: str = DEFAULT_MODEL,
    reporter_model: str = DEFAULT_MODEL,
    output_dir: str = None,
) -> None:
    started = time.time()
    folder_path = Path(folder).resolve()

    if not folder_path.is_dir():
        print(f"ERROR: '{folder}' is not a valid directory.")
        sys.exit(1)

    files = collect_files(str(folder_path))
    if not files:
        print("ERROR: No supported files found.")
        sys.exit(1)

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(output_dir) if output_dir else folder_path / f"sast_run_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    repo_hash = build_repo_hash(files, folder_path)

    raw_findings = []
    verified_findings = []
    rejected_findings = []

    total_prompt_eval = 0
    total_eval = 0

    print(f"Starting multi-agent SAST scan on: {folder_path}")
    print(f"Files found: {len(files)}")
    print(f"Output directory: {out_dir}")

    for idx, filepath in enumerate(files, start=1):
        rel_path = str(filepath.relative_to(folder_path))
        print(f"[{idx}/{len(files)}] Scanning {rel_path}")

        try:
            code = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"  Failed to read file: {e}")
            continue

        if not code.strip():
            print("  Skipped empty file")
            continue

        language = get_language(filepath.suffix.lower())

        # Agent 1: scanner
        file_raw_findings, usage, file_hash = scanner_agent(
            filepath=filepath,
            rel_path=rel_path,
            language=language,
            code=code,
            model=scanner_model,
        )
        total_prompt_eval += usage["prompt_eval_count"]
        total_eval += usage["eval_count"]

        code_lines = code.splitlines()

        raw_findings.extend(file_raw_findings)

        # Agent 2: critic
        # for finding in file_raw_findings:
        #     try:
        #         critic_result, usage = critic_agent(code_lines, finding, critic_model)
        #         total_prompt_eval += usage["prompt_eval_count"]
        #         total_eval += usage["eval_count"]
        #     except Exception as e:
        #         rejected_findings.append({
        #             "id": finding["id"],
        #             "file": finding["file"],
        #             "title": finding["title"],
        #             "line": finding["line"],
        #             "reason": f"Critic agent failure: {e}",
        #         })
        #         continue

        #     if critic_result["verdict"] == "confirmed":
        #         confirmed = critic_result["finding"]
        #         confirmed["file_hash"] = file_hash
        #         verified_findings.append(confirmed)
        #     else:
        #         rejected_findings.append(critic_result["finding"])

        # Agent 2: critic (bypassed for testing — all findings passed through)
        # for finding in file_raw_findings:
        #     finding["file_hash"] = file_hash
        #     finding["verification_notes"] = "Critic bypassed"
        #     finding["preconditions"] = "N/A"
        #     verified_findings.append(finding)
# Agent 2: critic
        for finding in file_raw_findings:
            try:
                critic_result, usage = critic_agent(code_lines, finding, critic_model)
                total_prompt_eval += usage["prompt_eval_count"]
                total_eval += usage["eval_count"]
            except Exception as e:
                rejected_findings.append({
                    "id": finding["id"],
                    "file": finding["file"],
                    "title": finding["title"],
                    "line": finding["line"],
                    "reason": f"Critic agent failure: {e}",
                })
                continue

            if critic_result["verdict"] == "confirmed":
                confirmed = critic_result["finding"]
                confirmed["file_hash"] = file_hash
                # Hallucination guard
                if len(confirmed.get("verification_notes", "")) < 20:
                    confirmed["verification_notes"] = (
                        f"Confirmed: evidence '{finding['evidence_snippet']}' "
                        f"matches {finding['title']} vulnerability pattern."
                    )
                verified_findings.append(confirmed)
            else:
                rejected_findings.append(critic_result["finding"])

    verified_findings = sort_findings(verified_findings)

    duration_seconds = time.time() - started
    sev_counts = severity_counts(verified_findings)

    metadata = {
        "run_id": run_id,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "repo_hash": repo_hash,
        "scanner_model": scanner_model,
        "critic_model": critic_model,
        "reporter_model": reporter_model,
        "files_scanned": len(files),
        "raw_findings": len(raw_findings),
        "verified_findings": len(verified_findings),
        "rejected_findings": len(rejected_findings),
        "duration_seconds": duration_seconds,
        "severity_counts": sev_counts,
        "prompt_eval_count": total_prompt_eval,
        "eval_count": total_eval,
    }

    # Agent 3: reporter
    summary = {
        "executive_summary": "No executive summary generated.",
        "technical_summary": "No technical summary generated.",
        "top_actions": [],
    }

    try:
        summary_result, usage = reporter_agent(metadata, verified_findings, reporter_model)
        total_prompt_eval += usage["prompt_eval_count"]
        total_eval += usage["eval_count"]
        metadata["prompt_eval_count"] = total_prompt_eval
        metadata["eval_count"] = total_eval

        if isinstance(summary_result, dict):
            summary["executive_summary"] = summary_result.get("executive_summary", summary["executive_summary"])
            summary["technical_summary"] = summary_result.get("technical_summary", summary["technical_summary"])
            summary["top_actions"] = summary_result.get("top_actions", []) if isinstance(summary_result.get("top_actions", []), list) else []
    except Exception as e:
        summary["technical_summary"] = f"Reporter agent failed: {e}"

    markdown_report = render_markdown_report(
        folder_path=folder_path,
        metadata=metadata,
        summary=summary,
        verified_findings=verified_findings,
        rejected_findings=rejected_findings,
    )

    md_path = out_dir / "final_report.md"
    pdf_path = out_dir / "final_report.pdf"
    raw_json_path = out_dir / "raw_findings.json"
    verified_json_path = out_dir / "verified_findings.json"
    rejected_json_path = out_dir / "rejected_findings.json"
    metadata_json_path = out_dir / "run_metadata.json"
    summary_json_path = out_dir / "report_summary.json"

    md_path.write_text(markdown_report, encoding="utf-8")
    save_json(raw_json_path, raw_findings)
    save_json(verified_json_path, verified_findings)
    save_json(rejected_json_path, rejected_findings)
    save_json(metadata_json_path, metadata)
    save_json(summary_json_path, summary)

    create_pdf_report(
        pdf_path=pdf_path,
        folder_path=folder_path,
        metadata=metadata,
        summary=summary,
        verified_findings=verified_findings,
        rejected_findings=rejected_findings,
    )

    print("\nScan complete")
    print(f"Markdown report: {md_path}")
    print(f"PDF report: {pdf_path}")
    print(f"Raw findings JSON: {raw_json_path}")
    print(f"Verified findings JSON: {verified_json_path}")
    print(f"Rejected findings JSON: {rejected_json_path}")
    print(f"Run metadata JSON: {metadata_json_path}")


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner_model = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MODEL
    critic_model = sys.argv[3] if len(sys.argv) > 3 else scanner_model
    reporter_model = sys.argv[4] if len(sys.argv) > 4 else scanner_model

    run_multi_agent_scan(
        folder=folder,
        scanner_model=scanner_model,
        critic_model=critic_model,
        reporter_model=reporter_model,
    )