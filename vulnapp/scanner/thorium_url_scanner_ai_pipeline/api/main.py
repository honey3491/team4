import os
import re
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, Query
from pydantic import BaseModel, HttpUrl

try:
    from openai import OpenAI
except Exception:
    OpenAI = None


DB_PATH = os.getenv("DB_PATH", "/data/findings.db")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
TIMEOUT = 6
MAX_FORMS = 8

app = FastAPI(title="Thorium-lite URL Vulnerability Scanner")

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

SENSITIVE_PATHS = [
    "/.git/",
    "/.env",
    "/backup/",
    "/admin/",
    "/phpinfo.php",
    "/server-status",
    "/robots.txt"
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-01756",
    "postgresql query failed",
    "sqlite error",
]

XSS_PAYLOAD = "<script>alert(1)</script>"
SQLI_PAYLOAD = "'"
TRAVERSAL_PAYLOAD = "../../../../etc/passwd"
CMDI_PAYLOAD = ";whoami"


class ScanRequest(BaseModel):
    target_url: HttpUrl
    enable_ai: bool = True


def now():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        created_at TEXT,
        target_url TEXT,
        finding_type TEXT,
        risk TEXT,
        evidence TEXT,
        url TEXT,
        tags TEXT,
        ai_summary TEXT,
        recommendation TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        created_at TEXT,
        target_url TEXT,
        status TEXT,
        findings_count INTEGER
    )
    """)
    conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


def normalize_url(url: str) -> str:
    return str(url).rstrip("/")


def safe_get(url: str) -> Optional[requests.Response]:
    try:
        return requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Thorium-Lite-Scanner/1.0"}
        )
    except Exception:
        return None


def make_finding(finding_type, risk, evidence, url, tags, recommendation):
    return {
        "created_at": now(),
        "finding_type": finding_type,
        "risk": risk,
        "evidence": evidence,
        "url": url,
        "tags": tags,
        "recommendation": recommendation,
        "ai_summary": ""
    }


def check_alive(url):
    r = safe_get(url)
    if r is None:
        return [make_finding(
            "Connection Failed", "Info",
            "대상 URL 접속 실패",
            url, ["connectivity"],
            "URL, 방화벽, 보안그룹, 서비스 상태를 확인"
        )], None

    return [make_finding(
        "Alive Check", "Info",
        f"HTTP {r.status_code}, final_url={r.url}",
        r.url, ["alive"],
        "정상 접속 여부 확인용 정보"
    )], r


def check_headers(url, response):
    findings = []
    headers = response.headers

    for h in SECURITY_HEADERS:
        if h not in headers:
            risk = "Medium" if h in [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options"
            ] else "Low"
            findings.append(make_finding(
                "Missing Security Header",
                risk,
                f"{h} header is missing",
                url,
                ["header", "misconfiguration"],
                f"{h} 헤더를 서비스 특성에 맞게 설정"
            ))

    server = headers.get("Server")
    if server:
        findings.append(make_finding(
            "Server Banner Disclosure",
            "Low",
            f"Server: {server}",
            url,
            ["banner", "information-disclosure"],
            "Server 헤더에서 상세 버전 정보 노출 최소화"
        ))

    return findings


def check_sensitive_paths(base_url):
    findings = []
    for path in SENSITIVE_PATHS:
        target = urljoin(base_url + "/", path.lstrip("/"))
        try:
            r = requests.get(target, timeout=TIMEOUT, allow_redirects=False, headers={"User-Agent": "Thorium-Lite-Scanner/1.0"})
            if r.status_code in [200, 301, 302, 403]:
                risk = "High" if path in ["/.git/", "/.env"] and r.status_code == 200 else "Medium"
                findings.append(make_finding(
                    "Sensitive Path Exposure",
                    risk,
                    f"{path} returned HTTP {r.status_code}",
                    target,
                    ["exposure", "misconfiguration"],
                    "민감 경로 접근 차단, 파일 제거, 웹서버 deny rule 적용"
                ))
        except Exception:
            continue
    return findings


def check_directory_listing(base_url):
    findings = []
    for path in ["/", "/uploads/", "/files/", "/backup/", "/static/"]:
        target = urljoin(base_url + "/", path.lstrip("/"))
        r = safe_get(target)
        if not r:
            continue
        body = r.text.lower()
        if "index of /" in body or "<title>index of" in body:
            findings.append(make_finding(
                "Directory Listing",
                "High",
                "Index listing pattern detected",
                target,
                ["directory-listing", "misconfiguration"],
                "Apache Options -Indexes 또는 Nginx autoindex off 적용"
            ))
    return findings


def inject_query_param(url, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    if not qs:
        qs = {"q": ["test"]}

    new_qs = {}
    for k in qs.keys():
        new_qs[k] = [payload]

    new_query = urlencode(new_qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def check_reflected_xss(url):
    target = inject_query_param(url, XSS_PAYLOAD)
    r = safe_get(target)
    if not r:
        return []

    if XSS_PAYLOAD in r.text:
        return [make_finding(
            "Reflected XSS",
            "High",
            "Payload reflected without encoding",
            target,
            ["xss", "owasp-a03"],
            "출력 컨텍스트 기반 인코딩, CSP 적용, 입력값 정규화"
        )]
    return []


def check_sqli_error(url):
    target = inject_query_param(url, SQLI_PAYLOAD)
    r = safe_get(target)
    if not r:
        return []

    body = r.text.lower()
    for sig in SQL_ERRORS:
        if sig in body:
            return [make_finding(
                "SQL Injection Error Signal",
                "High",
                f"SQL error signature detected: {sig}",
                target,
                ["sqli", "owasp-a03"],
                "Prepared Statement, 파라미터 바인딩, DB 에러 메시지 비노출"
            )]
    return []


def check_traversal_signal(url):
    target = inject_query_param(url, TRAVERSAL_PAYLOAD)
    r = safe_get(target)
    if not r:
        return []

    body = r.text.lower()
    if "root:x:0:0:" in body or "/bin/bash" in body:
        return [make_finding(
            "Directory Traversal",
            "High",
            "Possible /etc/passwd content detected",
            target,
            ["path-traversal", "owasp-a01"],
            "파일 경로 입력 allowlist 처리, 경로 정규화 후 검증, 웹루트 밖 파일 접근 차단"
        )]
    return []


def check_command_injection_reflection(url):
    target = inject_query_param(url, CMDI_PAYLOAD)
    r = safe_get(target)
    if not r:
        return []

    body = r.text.lower()
    if any(x in body for x in ["www-data", "apache", "nginx", "root"]):
        return [make_finding(
            "Command Injection Signal",
            "Critical",
            "Possible command output reflected in response",
            target,
            ["command-injection", "owasp-a03"],
            "OS 명령 직접 실행 제거, shell=False, allowlist 검증, 최소권한 계정 사용"
        )]
    return []


def discover_forms(url):
    r = safe_get(url)
    if not r:
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    forms = []
    for form in soup.find_all("form")[:MAX_FORMS]:
        action = form.get("action") or url
        method = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append(name)
        forms.append({
            "action": urljoin(url, action),
            "method": method,
            "inputs": inputs
        })
    return forms


def check_forms(url):
    findings = []
    forms = discover_forms(url)
    for form in forms:
        findings.append(make_finding(
            "Input Form Found",
            "Info",
            json.dumps(form, ensure_ascii=False),
            form["action"],
            ["form", "attack-surface"],
            "입력값 검증, CSRF 방어, 인증/인가 검증, 출력 인코딩 필요"
        ))

        if form["action"].startswith("http://") and any("pass" in x.lower() or "pwd" in x.lower() for x in form["inputs"]):
            findings.append(make_finding(
                "Sensitive Form Over HTTP",
                "High",
                f"Sensitive fields over HTTP: {form['inputs']}",
                form["action"],
                ["http", "credential"],
                "로그인/민감정보 입력 폼은 HTTPS로만 제공"
            ))
    return findings


def ai_analyze(finding: Dict[str, Any], enabled: bool) -> str:
    if not enabled:
        return ""
    if not OPENAI_API_KEY or OpenAI is None:
        return f"{finding['finding_type']} 탐지. 근거: {finding['evidence']}"

    prompt = f"""
너는 웹 취약점 진단 컨설턴트다. 아래 자동 진단 결과를 보고 짧게 분석하라.

진단 항목: {finding['finding_type']}
위험도: {finding['risk']}
대상 URL: {finding['url']}
근거: {finding['evidence']}
권장 대응: {finding['recommendation']}

출력:
- 판단 요약
- 보안 영향
- 대응 방안
"""

    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "한국어로 간결하게 보안 진단 결과를 작성한다."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"AI 분석 실패: {e}"


def save_scan(scan_id, target_url, status, findings):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO scans(id, created_at, target_url, status, findings_count) VALUES (?, ?, ?, ?, ?)",
        (scan_id, now(), target_url, status, len(findings))
    )
    for f in findings:
        cur.execute("""
        INSERT INTO findings (
            scan_id, created_at, target_url, finding_type, risk, evidence,
            url, tags, ai_summary, recommendation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, f["created_at"], target_url, f["finding_type"], f["risk"],
            f["evidence"], f["url"], json.dumps(f["tags"], ensure_ascii=False),
            f.get("ai_summary", ""), f["recommendation"]
        ))
    conn.commit()
    conn.close()


@app.post("/scan")
def scan(req: ScanRequest):
    target_url = normalize_url(str(req.target_url))
    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")

    findings, response = check_alive(target_url)

    if response is not None:
        base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

        checks = [
            lambda: check_headers(target_url, response),
            lambda: check_sensitive_paths(base_url),
            lambda: check_directory_listing(base_url),
            lambda: check_reflected_xss(target_url),
            lambda: check_sqli_error(target_url),
            lambda: check_traversal_signal(target_url),
            lambda: check_command_injection_reflection(target_url),
            lambda: check_forms(target_url),
        ]

        for check in checks:
            try:
                findings.extend(check())
            except Exception as e:
                findings.append(make_finding(
                    "Scanner Error",
                    "Info",
                    str(e),
                    target_url,
                    ["scanner-error"],
                    "스캐너 예외 로그 확인"
                ))

    for f in findings:
        f["ai_summary"] = ai_analyze(f, req.enable_ai)

    save_scan(scan_id, target_url, "done", findings)

    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "findings_count": len(findings),
        "findings": findings
    }


@app.get("/findings")
def get_findings(
    q: Optional[str] = None,
    risk: Optional[str] = None,
    finding_type: Optional[str] = None,
    limit: int = Query(default=300, le=1000)
):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    sql = "SELECT * FROM findings WHERE 1=1"
    params = []
    if q:
        sql += " AND (target_url LIKE ? OR url LIKE ? OR finding_type LIKE ? OR tags LIKE ? OR ai_summary LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
    if risk:
        sql += " AND risk = ?"
        params.append(risk)
    if finding_type:
        sql += " AND finding_type = ?"
        params.append(finding_type)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = cur.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/stats")
def stats():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"]
    by_type = cur.execute("SELECT finding_type, COUNT(*) AS c FROM findings GROUP BY finding_type").fetchall()
    by_risk = cur.execute("SELECT risk, COUNT(*) AS c FROM findings GROUP BY risk").fetchall()
    recent_scans = cur.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 10").fetchall()
    conn.close()
    return {
        "total": total,
        "by_type": [dict(r) for r in by_type],
        "by_risk": [dict(r) for r in by_risk],
        "recent_scans": [dict(r) for r in recent_scans]
    }


@app.get("/cve")
def cve_lookup(keyword: str):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        r = requests.get(url, params={"keywordSearch": keyword}, timeout=10)
        data = r.json()
        vulns = data.get("vulnerabilities", [])[:10]
        result = []
        for item in vulns:
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            score = None
            severity = None
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity")
            result.append({
                "id": cve.get("id"),
                "published": cve.get("published"),
                "severity": severity,
                "score": score,
                "description": cve.get("descriptions", [{}])[0].get("value", "")[:300]
            })
        return result
    except Exception as e:
        return {"error": str(e)}
