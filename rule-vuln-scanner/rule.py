import argparse
import json
import subprocess
import time
from urllib.parse import urljoin, urlparse

import requests


TIMEOUT = 5
HEADERS = {"User-Agent": "VulnSignatureScanner/1.0"}
SQL_ERRORS = [
    "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
    "You have an error in your SQL syntax", "ODBC", "JDBC", "SQLException"
]
XSS_PAYLOAD = "<script>alert(1337)</script>"


def req(method, url, **kwargs):
    try:
        r = requests.request(
            method,
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=False,
            **kwargs
        )
        return r
    except Exception as e:
        return {"error": str(e)}


def result(check_id, owasp, name, target, vulnerable, evidence="", severity="info"):
    return {
        "check_id": check_id,
        "owasp": owasp,
        "name": name,
        "target": target,
        "vulnerable": vulnerable,
        "severity": severity,
        "evidence": evidence
    }


def check_https(base):
    parsed = urlparse(base)
    return result(
        "WEB-009",
        "A02:2021 Cryptographic Failures",
        "HTTPS 미적용",
        "전체 서비스",
        parsed.scheme != "https",
        f"scheme={parsed.scheme}",
        "medium" if parsed.scheme != "https" else "info"
    )


def check_security_headers(base):
    r = req("GET", base)
    if isinstance(r, dict):
        return result("WEB-001", "A05:2021 Security Misconfiguration", "보안 헤더 점검", base, False, r["error"])

    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security"
    ]

    missing = [h for h in required if h not in r.headers]

    return result(
        "WEB-001",
        "A05:2021 Security Misconfiguration",
        "보안 헤더 미설정",
        "Nginx/Tomcat 응답 헤더",
        bool(missing),
        f"missing={missing}",
        "medium" if missing else "info"
    )


def check_server_info(base):
    r = req("GET", base)
    if isinstance(r, dict):
        return result("WEB-002", "A05:2021 Security Misconfiguration", "서버 정보 노출", base, False, r["error"])

    exposed = {}
    for h in ["Server", "X-Powered-By", "X-AspNet-Version"]:
        if h in r.headers:
            exposed[h] = r.headers[h]

    body = r.text[:2000]
    error_keywords = ["Apache Tomcat/", "nginx/", "Stacktrace", "Exception", "Traceback"]
    found = [k for k in error_keywords if k.lower() in body.lower()]

    return result(
        "WEB-002",
        "A05:2021 Security Misconfiguration",
        "서버 정보 노출",
        "HTTP Header / Error Page",
        bool(exposed or found),
        f"headers={exposed}, body_keywords={found}",
        "low" if exposed or found else "info"
    )


def check_admin_page(base):
    path = "/vulnapp/admin.jsp"
    url = urljoin(base, path)
    r = req("GET", url)

    if isinstance(r, dict):
        return result("WEB-001", "A01:2021 Broken Access Control", "관리자 페이지 노출", path, False, r["error"])

    vulnerable = r.status_code == 200 and "login" not in r.text.lower()
    return result(
        "WEB-001",
        "A01:2021 Broken Access Control",
        "관리자 페이지 노출",
        path,
        vulnerable,
        f"status={r.status_code}, location={r.headers.get('Location')}",
        "high" if vulnerable else "info"
    )


def check_idor(base):
    urls = [
        urljoin(base, "/vulnapp/user.jsp?id=1"),
        urljoin(base, "/vulnapp/user.jsp?id=2")
    ]

    r1 = req("GET", urls[0])
    r2 = req("GET", urls[1])

    if isinstance(r1, dict) or isinstance(r2, dict):
        return result("WEB-002", "A01:2021 Broken Access Control", "다른 사용자 정보 조회", "IDOR", False, "request failed")

    vulnerable = (
        r1.status_code == 200 and
        r2.status_code == 200 and
        r1.text != r2.text and
        any(k in (r1.text + r2.text).lower() for k in ["user", "email", "name", "phone", "address"])
    )

    return result(
        "WEB-002",
        "A01:2021 Broken Access Control",
        "다른 사용자 정보 조회",
        "IDOR",
        vulnerable,
        f"id=1 status={r1.status_code}, id=2 status={r2.status_code}",
        "high" if vulnerable else "info"
    )


def check_sqli(base, run_sqlmap=False):
    path = "/vulnapp/login.jsp"
    url = urljoin(base, path)

    payloads = [
        "' OR '1'='1",
        "' OR 1=1 -- ",
        "\" OR \"1\"=\"1",
        "' AND SLEEP(2)-- "
    ]

    findings = []
    suspected = False

    for p in payloads:
        start = time.time()
        r = req("POST", url, data={"username": p, "password": p})
        elapsed = time.time() - start

        if isinstance(r, dict):
            continue

        body = r.text[:3000]
        error_hit = [e for e in SQL_ERRORS if e.lower() in body.lower()]
        auth_bypass = r.status_code == 200 and any(k in body.lower() for k in ["welcome", "admin", "logout"])
        time_based = elapsed > 2

        if error_hit or auth_bypass or time_based:
            suspected = True
            findings.append({
                "payload": p,
                "status": r.status_code,
                "elapsed": round(elapsed, 2),
                "error_hit": error_hit,
                "auth_bypass_hint": auth_bypass
            })

    sqlmap_output = None
    if suspected and run_sqlmap:
        cmd = [
            "sqlmap",
            "-u", url,
            "--data", "username=test&password=test",
            "-p", "username,password",
            "--batch",
            "--level", "2",
            "--risk", "1"
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            sqlmap_output = {
                "cmd": " ".join(cmd),
                "returncode": proc.returncode,
                "stdout_tail": proc.stdout[-4000:],
                "stderr_tail": proc.stderr[-2000:]
            }
        except Exception as e:
            sqlmap_output = {"error": str(e)}

    return result(
        "WEB-003",
        "A03:2021 Injection",
        "SQL Injection",
        path,
        suspected,
        {"findings": findings, "sqlmap": sqlmap_output},
        "critical" if suspected else "info"
    )


def check_xss(base):
    path = "/vulnapp/search.jsp"
    url = urljoin(base, path)

    r = req("GET", url, params={"q": XSS_PAYLOAD})
    if isinstance(r, dict):
        return result("WEB-004", "A03:2021 Injection", "XSS", path, False, r["error"])

    vulnerable = XSS_PAYLOAD in r.text

    return result(
        "WEB-004",
        "A03:2021 Injection",
        "XSS",
        path,
        vulnerable,
        f"reflected_payload={vulnerable}, status={r.status_code}",
        "high" if vulnerable else "info"
    )


def check_tomcat_default(base):
    r = req("GET", base)
    if isinstance(r, dict):
        return result("WEB-007", "A05:2021 Security Misconfiguration", "Tomcat 기본 페이지 노출", "기본 페이지", False, r["error"])

    vulnerable = "Apache Tomcat" in r.text and "If you're seeing this" in r.text

    return result(
        "WEB-007",
        "A05:2021 Security Misconfiguration",
        "Tomcat 기본 페이지 노출",
        "기본 페이지",
        vulnerable,
        f"status={r.status_code}",
        "medium" if vulnerable else "info"
    )


def check_tomcat_manager(base):
    path = "/manager/html"
    url = urljoin(base, path)
    r = req("GET", url)

    if isinstance(r, dict):
        return result("WEB-008", "A05:2021 Security Misconfiguration", "Tomcat Manager 페이지 노출", path, False, r["error"])

    vulnerable = r.status_code in [200, 401, 403]

    return result(
        "WEB-008",
        "A05:2021 Security Misconfiguration",
        "Tomcat Manager 페이지 노출",
        path,
        vulnerable,
        f"status={r.status_code}, www-authenticate={r.headers.get('WWW-Authenticate')}",
        "medium" if vulnerable else "info"
    )


def check_cookie_flags(base):
    r = req("GET", base)
    if isinstance(r, dict):
        return result("WEB-010", "A07:2021 Identification and Authentication Failures", "쿠키 보안 속성 미설정", "Set-Cookie Header", False, r["error"])

    cookies = r.headers.get("Set-Cookie", "")
    if not cookies:
        return result(
            "WEB-010",
            "A07:2021 Identification and Authentication Failures",
            "쿠키 보안 속성 미설정",
            "Set-Cookie Header",
            False,
            "Set-Cookie 없음"
        )

    missing = []
    lower = cookies.lower()

    if "httponly" not in lower:
        missing.append("HttpOnly")
    if "secure" not in lower:
        missing.append("Secure")
    if "samesite" not in lower:
        missing.append("SameSite")

    return result(
        "WEB-010",
        "A07:2021 Identification and Authentication Failures",
        "쿠키 보안 속성 미설정",
        "Set-Cookie Header",
        bool(missing),
        f"missing={missing}, set-cookie={cookies}",
        "medium" if missing else "info"
    )


def check_upload_integrity(base):
    path = "/vulnapp/upload.jsp"
    url = urljoin(base, path)

    files = {
        "file": ("safe_probe.txt", b"SAFE_UPLOAD_PROBE_1337", "text/plain")
    }

    r = req("POST", url, files=files)

    if isinstance(r, dict):
        return result("WEB-011", "A08:2021 Software and Data Integrity Failures", "파일 업로드 검증 미흡", path, False, r["error"])

    vulnerable = r.status_code in [200, 201] and any(
        k in r.text.lower() for k in ["uploaded", "success", "safe_probe.txt"]
    )

    return result(
        "WEB-011",
        "A08:2021 Software and Data Integrity Failures",
        "파일 업로드 검증 미흡",
        "파일 업로드",
        vulnerable,
        f"status={r.status_code}, benign txt upload accepted={vulnerable}",
        "medium" if vulnerable else "info"
    )


def check_ssrf(base):
    path = "/fetch"
    url = urljoin(base, path)

    payload = "http://169.254.169.254/latest/meta-data/"
    r = req("GET", url, params={"url": payload})

    if isinstance(r, dict):
        return result("WEB-012", "A10:2021 SSRF", "SSRF", "/fetch?url=", False, r["error"])

    indicators = [
        "ami-id",
        "instance-id",
        "hostname",
        "iam/",
        "security-credentials"
    ]

    body = r.text[:3000].lower()
    hits = [i for i in indicators if i in body]

    return result(
        "WEB-012",
        "A10:2021 SSRF",
        "AWS Metadata SSRF",
        "/fetch?url=http://169.254.169.254/latest/meta-data/",
        bool(hits),
        f"status={r.status_code}, indicators={hits}",
        "critical" if hits else "info"
    )


def scan(base_url, output, run_sqlmap):
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url

    checks = [
        check_https(base_url),
        check_security_headers(base_url),
        check_server_info(base_url),
        check_admin_page(base_url),
        check_idor(base_url),
        check_sqli(base_url, run_sqlmap),
        check_xss(base_url),
        check_tomcat_default(base_url),
        check_tomcat_manager(base_url),
        check_cookie_flags(base_url),
        check_upload_integrity(base_url),
        check_ssrf(base_url)
    ]

    report = {
        "target": base_url,
        "scanner": "signature-based-web-vuln-scanner",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total": len(checks),
            "vulnerable": sum(1 for c in checks if c["vulnerable"])
        },
        "results": checks
    }

    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n[+] saved: {output}")


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()

    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="진단 대상 URL 예: http://localhost:8080")
    parser.add_argument("-o", "--output", default="scan_result.json")
    parser.add_argument("--sqlmap", action="store_true", help="SQLi 의심 시 sqlmap 실행")
    args = parser.parse_args()

    scan(args.url, args.output, args.sqlmap)