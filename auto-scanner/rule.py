import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


TIMEOUT = 20
HEADERS = {"User-Agent": "SignatureBasedWebVulnScanner/2.0"}
KST = timezone(timedelta(hours=9))

SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "PostgreSQL",
    "SQLite",
    "SQLException",
    "You have an error in your SQL syntax",
    "ODBC",
    "JDBC"
]

XSS_PAYLOAD = "<script>alert(1337)</script>"


def req(method, url, **kwargs):
    try:
        headers = {**HEADERS, **kwargs.pop("headers", {})}
        return requests.request(
            method,
            url,
            headers=headers,
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=False,
            **kwargs
        )
    except Exception:
        return None


def normalize_base_url(base_url):
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url

    return base_url.rstrip("/") + "/"


def next_output_path(output):
    if not os.path.exists(output):
        return output

    stem, ext = os.path.splitext(output)
    index = 1

    while True:
        candidate = f"{stem}_{index}{ext}"
        if not os.path.exists(candidate):
            return candidate
        index += 1


def make_scan_id():
    return "SCAN-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def now_utc():
    return datetime.now(KST).strftime("%Y-%m-%dT%H:%M:%S+09:00")


def result(check_id, owasp, name, severity, evidence, recommendation, url=""):
    return {
        "check_id": check_id,
        "owasp": owasp,
        "name": name,
        "url": url,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation
    }


def add_result_ids(results):
    final = []

    for idx, r in enumerate(results, start=1):
        final.append({
            "id": f"RES-{idx:04d}",
            "check_id": r["check_id"],
            "owasp": r["owasp"],
            "name": r["name"],
            "url": r.get("url", ""),
            "severity": r["severity"],
            "evidence": r["evidence"],
            "recommendation": r["recommendation"]
        })

    return final


def build_summary(results):
    severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for r in results:
        sev = r.get("severity")
        if sev in severity:
            severity[sev] += 1

    return {
        "total": len(results),
        "severity": severity
    }


# A01 Broken Access Control

def check_admin_page(base):
    url = urljoin(base, "/vulnapp/admin.jsp")

    r = req("GET", url)

    if not r:
        return None

    vulnerable = r.status_code == 200 and "login" not in r.text.lower()

    if vulnerable:
        return result(
            "WEB-A01-001",
            "A01:2025 Broken Access Control",
            "관리자 페이지 직접 접근",
            "medium",
            f"/vulnapp/admin.jsp 접근 가능, status={r.status_code}",
            "관리자 페이지에 인증 및 권한 검증 적용"
        )

    return None


def check_idor(base):
    url1 = urljoin(base, "/vulnapp/profile.jsp?user_idx=1")
    url2 = urljoin(base, "/vulnapp/profile.jsp?user_idx=2")

    r1 = req("GET", url1)
    r2 = req("GET", url2)

    if not r1 or not r2:
        return None

    body = (r1.text + r2.text).lower()

    vulnerable = (
        r1.status_code == 200 and
        r2.status_code == 200 and
        r1.text != r2.text and
        any(k in body for k in ["user", "email", "name", "phone", "address", "order"])
    )

    if vulnerable:
        return result(
            "WEB-A01-002",
            "A01:2025 Broken Access Control",
            "IDOR로 타 사용자 정보 조회",
            "medium",
            "user_idx 파라미터 변경으로 다른 사용자 정보 응답 확인",
            "서버 측에서 요청 사용자와 자원 소유자 권한 검증"
        )

    return None


# A02 Security Misconfiguration

def check_security_headers(base):
    r = req("GET", base)

    if not r:
        return None

    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]

    missing = [h for h in required if h not in r.headers]
    csp = r.headers.get("Content-Security-Policy", "")

    issues = []

    if missing:
        issues.append(f"missing={missing}")

    if "unsafe-inline" in csp:
        issues.append("CSP unsafe-inline 허용")

    if issues:
        return result(
            "WEB-A02-001",
            "A02:2025 Security Misconfiguration",
            "보안 헤더 미설정",
            "low",
            ", ".join(issues),
            "필수 보안 헤더 적용 및 CSP nonce/hash 기반 설정"
        )

    return None


def check_server_info(base):
    r = req("GET", base)

    if not r:
        return None

    exposed = {}

    for h in ["Server", "X-Powered-By", "X-AspNet-Version"]:
        if h in r.headers:
            exposed[h] = r.headers[h]

    keywords = ["Apache Tomcat/", "nginx/", "Stacktrace", "Exception", "Traceback"]
    found = [k for k in keywords if k.lower() in r.text[:3000].lower()]

    if exposed or found:
        return result(
            "WEB-A02-002",
            "A02:2025 Security Misconfiguration",
            "서버 버전 노출",
            "low",
            f"headers={exposed}, body_keywords={found}",
            "서버 배너 제거 및 커스텀 에러 페이지 적용"
        )

    return None


def check_tomcat_manager(base):
    url = urljoin(base, "/manager/html")
    r = req("GET", url)

    if not r:
        return None

    if r.status_code in [200, 401, 403]:
        return result(
            "WEB-A02-003",
            "A02:2025 Security Misconfiguration",
            "Tomcat Manager 노출",
            "high",
            f"/manager/html 접근 가능, status={r.status_code}",
            "Tomcat Manager 비활성화 또는 접근 IP 제한"
        )

    return None


# A03 Software Supply Chain Failures

def check_log4j(base):
    payload = "${jndi:ldap://127.0.0.1:1389/a}"
    test_urls = [
        urljoin(base, "/vulnapp/login.jsp"),
        urljoin(base, "/vulnapp/search.jsp")
    ]

    for url in test_urls:
        r = req(
            "GET",
            url,
            headers={
                **HEADERS,
                "User-Agent": payload,
                "X-Api-Version": payload
            }
        )

        if r and r.status_code >= 500:
            return result(
                "WEB-A03-001",
                "A03:2025 Software Supply Chain Failures",
                "취약한 Log4j 사용",
                "high",
                "JNDI payload 입력 후 서버 오류 발생",
                "Log4j 2.17.1 이상 업데이트 및 JNDI Lookup 비활성화"
            )

    return None


def check_old_jquery(base):
    r = req("GET", base)

    if not r:
        return None

    soup = BeautifulSoup(r.text, "html.parser")
    scripts = [s.get("src", "") for s in soup.find_all("script")]

    old_hits = []

    for src in scripts:
        lowered = src.lower()
        if "jquery-1." in lowered or "jquery-2." in lowered:
            old_hits.append(src)

    if old_hits:
        return result(
            "WEB-A03-002",
            "A03:2025 Software Supply Chain Failures",
            "구버전 jQuery 사용",
            "medium",
            f"old_jquery={old_hits}",
            "jQuery 최신 안정 버전으로 업데이트"
        )

    return None


# A04 Cryptographic Failures

def check_https(base):
    parsed = urlparse(base)

    if parsed.scheme != "https":
        return result(
            "WEB-A04-001",
            "A04:2025 Cryptographic Failures",
            "HTTPS 미적용",
            "medium",
            "HTTP 프로토콜 사용",
            "HTTPS 적용 및 HTTP to HTTPS 리다이렉트 설정"
        )

    return None


def check_cookie_flags(base):
    r = req("GET", base)

    if not r:
        return None

    cookies = r.headers.get("Set-Cookie", "")

    if not cookies:
        return None

    lower = cookies.lower()
    missing = []

    if "secure" not in lower:
        missing.append("Secure")

    if "httponly" not in lower:
        missing.append("HttpOnly")

    if "samesite" not in lower:
        missing.append("SameSite")

    if missing:
        return result(
            "WEB-A04-002",
            "A04:2025 Cryptographic Failures",
            "쿠키 Secure/HttpOnly 미설정",
            "medium",
            f"missing={missing}",
            "쿠키에 Secure, HttpOnly, SameSite 속성 적용"
        )

    return None


# A05 Injection

def extract_login_form(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
    except Exception:
        return None

    soup = BeautifulSoup(r.text, "html.parser")
    form = soup.find("form")

    if not form:
        return None

    action = form.get("action", "")
    method = form.get("method", "GET").upper()

    params = []

    for i in form.find_all("input"):
        name = i.get("name")
        input_type = i.get("type", "text")

        if name:
            params.append({
                "name": name,
                "type": input_type
            })

    return {
        "action": urljoin(url, action),
        "method": method,
        "params": params
    }


def check_sqli(base, run_sqlmap=False):
    login_url = urljoin(base, "/vulnapp/login.jsp")
    form = extract_login_form(login_url)

    if not form:
        return None

    payloads = [
        "' OR '1'='1",
        "' OR 1=1 -- ",
        "\" OR \"1\"=\"1",
        "' AND SLEEP(3)-- "
    ]

    for payload in payloads:
        data = {}

        for p in form["params"]:
            name = p["name"]
            typ = p.get("type", "text").lower()

            if typ in ["text", "password", "email", "search"]:
                data[name] = payload
            elif typ == "submit":
                continue
            else:
                data[name] = "test"

        start = time.time()

        try:
            if form["method"] == "POST":
                r = requests.post(
                    form["action"],
                    data=data,
                    headers=HEADERS,
                    timeout=30,
                    verify=False,
                    allow_redirects=False
                )
            else:
                r = requests.get(
                    form["action"],
                    params=data,
                    headers=HEADERS,
                    timeout=30,
                    verify=False,
                    allow_redirects=False
                )
        except Exception:
            continue

        elapsed = time.time() - start
        body = r.text[:3000].lower()
        location = r.headers.get("Location", "")
        redirected = r.status_code in [301, 302, 303, 307, 308] and bool(location)
        login_failed_absent = "login failed" not in body

        error_hit = any(e.lower() in body for e in SQL_ERRORS)
        auth_bypass = redirected or login_failed_absent
        time_based = elapsed > 3

        if error_hit or auth_bypass or time_based:
            sqlmap_info = None

            if run_sqlmap:
                sqlmap_info = run_sqlmap_probe(form)

            evidence = {
                "payload": payload,
                "error_based": error_hit,
                "auth_bypass": auth_bypass,
                "redirected": redirected,
                "redirect_location": location,
                "login_failed_absent": login_failed_absent,
                "time_based": time_based,
                "delay": round(elapsed, 2),
                "sqlmap": sqlmap_info
            }

            return result(
                "WEB-A05-001",
                "A05:2025 Injection",
                "SQL Injection",
                "high",
                evidence,
                "Prepared Statement 사용 및 입력값 검증"
            )

    return None

def run_sqlmap_probe(form):
    params = [
        p["name"]
        for p in form["params"]
        if p.get("name") and p.get("type", "text").lower() != "submit"
    ]

    data_str = "&".join([f"{name}=test" for name in params])

    cmd = [
        "sqlmap",
        "-u",
        form["action"],
        "--batch",
        "--level", "2",
        "--risk", "1",
        "--banner",
        "--current-user",
        "--current-db",
        "--is-dba",
        "--dbs"
    ]

    if form["method"] == "POST":
        cmd.extend(["--data", data_str])
    else:
        if "?" in form["action"]:
            cmd[2] = form["action"] + "&" + data_str
        else:
            cmd[2] = form["action"] + "?" + data_str

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=240
        )

        output = proc.stdout + "\n" + proc.stderr

        return {
            "command": " ".join(cmd),
            "returncode": proc.returncode,
            "dbms_banner": extract_sqlmap_value(output, "banner"),
            "current_user": extract_sqlmap_value(output, "current user"),
            "current_db": extract_sqlmap_value(output, "current database"),
            "is_dba": extract_sqlmap_value(output, "current user is DBA"),
            "databases": extract_sqlmap_databases(output),
            "raw_tail": output[-2000:]
        }

    except FileNotFoundError:
        return {
            "error": "sqlmap not installed"
        }

    except Exception as e:
        return {
            "error": str(e)
        }

import re

def extract_sqlmap_value(output, field):
    patterns = {
        "banner": r"^banner:\s*'?(.*?)'?\s*$",
        "current user": r"^current user:\s*'?(.*?)'?\s*$",
        "current database": r"^current database:\s*'?(.*?)'?\s*$",
        "current user is DBA": r"^current user is DBA:\s*(True|False)\s*$"
    }

    pattern = patterns.get(field)
    if not pattern:
        return None

    for line in output.splitlines():
        match = re.search(pattern, line.strip(), re.IGNORECASE)
        if match:
            value = match.group(1)

            if field == "current user is DBA":
                return value.lower() == "true"

            return value

    return None


def extract_sqlmap_databases(output):
    databases = []

    for line in output.splitlines():
        stripped = line.strip()

        if stripped.startswith("[*]"):
            value = stripped.replace("[*]", "").strip()

            if (
                value and
                "ending @" not in value.lower() and
                "starting @" not in value.lower() and
                "available databases" not in value.lower()
            ):
                databases.append(value)

    return databases


def extract_sqlmap_tables(output):
    tables = {}
    current_db = None

    for line in output.splitlines():
        stripped = line.strip()

        # Database: vuln_db
        if stripped.startswith("Database:"):
            current_db = stripped.split("Database:")[-1].strip()
            tables[current_db] = []

        # | users |
        elif stripped.startswith("|") and current_db:
            value = stripped.replace("|", "").strip()

            if (
                value and
                value.lower() != "table" and
                not value.startswith("-")
            ):
                tables[current_db].append(value)

    return tables

def check_reflected_xss(base):
    url = urljoin(base, "/vulnapp/search.jsp")
    r = req("GET", url, params={"q": XSS_PAYLOAD})

    if not r:
        return None

    if XSS_PAYLOAD in r.text:
        return result(
            "WEB-A05-002",
            "A05:2025 Injection",
            "Reflected XSS",
            "medium",
            "검색 파라미터 q에 입력한 script 태그가 응답에 그대로 반영됨",
            "출력 시 HTML Encoding 적용"
        )

    return None


def check_stored_xss(base):
    url = urljoin(base, "/vulnapp/board.jsp")
    data = {
        "title": "xss-test",
        "content": XSS_PAYLOAD
    }

    r = req("POST", url, data=data)

    if not r:
        return None

    check = req("GET", url)

    if check and XSS_PAYLOAD in check.text:
        return result(
            "WEB-A05-003",
            "A05:2025 Injection",
            "Stored XSS",
            "high",
            "게시글에 script 태그 저장 후 재조회 시 실행 가능",
            "저장 데이터 출력 시 HTML Encoding 및 입력 검증"
        )

    return None


def check_command_injection(base):
    url = urljoin(base, "/vulnapp/ping.jsp")
    payload = "127.0.0.1; id"
    r = req("GET", url, params={"host": payload})

    if not r:
        return None

    body = r.text.lower()

    if "uid=" in body or "gid=" in body or "root" in body:
        return result(
            "WEB-A05-004",
            "A05:2025 Injection",
            "Command Injection",
            "critical",
            "host 파라미터에 OS 명령어 삽입 후 명령 실행 결과 확인",
            "OS 명령 직접 실행 제거 및 allowlist 기반 입력 검증"
        )

    return None


# A06 Insecure Design

def check_rate_limit(base):
    url = urljoin(base, "/vulnapp/login.jsp")
    fail_count = 0

    for _ in range(8):
        r = req("POST", url, data={"username": "admin", "password": "wrongpass"})
        if r and r.status_code in [200, 401, 403]:
            fail_count += 1

    if fail_count >= 8:
        return result(
            "WEB-A06-001",
            "A06:2025 Insecure Design",
            "로그인 Rate Limit 미구현",
            "medium",
            "반복 로그인 실패 요청이 차단되지 않음",
            "로그인 실패 횟수 제한 및 지연 응답 적용"
        )

    return None


def check_debug_mode(base):
    url = urljoin(base, "/vulnapp/")
    r = req("GET", url, params={"debug": "true"})

    if not r:
        return None

    body = r.text.lower()

    if any(k in body for k in ["debug", "env", "classpath", "config", "stacktrace"]):
        return result(
            "WEB-A06-002",
            "A06:2025 Insecure Design",
            "debug=true 기능 활성화",
            "medium",
            "debug=true 요청 시 내부 설정 또는 디버그 정보 노출",
            "운영 환경에서 debug 기능 비활성화"
        )

    return None


# A07 Authentication Failures

def check_account_lockout(base):
    url = urljoin(base, "/vulnapp/login.jsp")
    attempts = 10
    blocked = False

    for _ in range(attempts):
        r = req("POST", url, data={"username": "admin", "password": "wrongpass"})
        if r and r.status_code in [429, 423]:
            blocked = True
            break

    if not blocked:
        return result(
            "WEB-A07-001",
            "A07:2025 Authentication Failures",
            "계정 잠금 미구현",
            "medium",
            "10회 이상 로그인 실패 후에도 계정 잠금 또는 차단 응답 없음",
            "계정 잠금, 지연 응답, CAPTCHA 적용"
        )

    return None


def check_weak_password(base):
    url = urljoin(base, "/vulnapp/register.jsp")
    weak_passwords = ["1234", "password", "admin123"]

    for pw in weak_passwords:
        r = req("POST", url, data={
            "username": f"test_{int(time.time())}",
            "password": pw
        })

        if r and r.status_code in [200, 201] and any(k in r.text.lower() for k in ["success", "created", "registered"]):
            return result(
                "WEB-A07-002",
                "A07:2025 Authentication Failures",
                "약한 비밀번호 허용",
                "medium",
                f"약한 비밀번호 허용: {pw}",
                "비밀번호 복잡도 및 사전 기반 약한 비밀번호 차단"
            )

    return None


def check_jwt_none(base):
    url = urljoin(base, "/vulnapp/api/profile")
    none_alg_token = (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ."
    )

    r = req("GET", url, headers={
        **HEADERS,
        "Authorization": f"Bearer {none_alg_token}"
    })

    if not r:
        return None

    if r.status_code == 200 and any(k in r.text.lower() for k in ["admin", "profile", "role"]):
        return result(
            "WEB-A07-003",
            "A07:2025 Authentication Failures",
            "JWT 검증 우회",
            "high",
            "alg=none JWT 토큰으로 인증된 응답 확인",
            "JWT 서명 알고리즘 고정 및 none 알고리즘 거부"
        )

    return None


# A08 Software or Data Integrity Failures

def check_webshell_upload(base):
    url = urljoin(base, "/vulnapp/upload.jsp")
    shell_name = "probe.jsp"
    shell_body = b"<% out.println(\"WEB_SHELL_PROBE_1337\"); %>"

    files = {
        "file": (shell_name, shell_body, "application/octet-stream")
    }

    r = req("POST", url, files=files)

    if not r:
        return None

    possible_paths = [
        urljoin(base, f"/vulnapp/uploads/{shell_name}"),
        urljoin(base, f"/uploads/{shell_name}"),
        urljoin(base, f"/vulnapp/{shell_name}")
    ]

    for p in possible_paths:
        check = req("GET", p)

        if check and "WEB_SHELL_PROBE_1337" in check.text:
            return result(
                "WEB-A08-001",
                "A08:2025 Software or Data Integrity Failures",
                "웹쉘 업로드 가능",
                "critical",
                ".jsp 파일 업로드 후 서버에서 실행됨",
                "실행 파일 업로드 차단, 확장자 allowlist, 업로드 경로 실행 권한 제거"
            )

    return None


# A09 Logging & Alerting Failures

def check_login_logging(base):
    url = urljoin(base, "/vulnapp/login.jsp")
    for _ in range(5):
        req("POST", url, data={"username": "admin", "password": "wrongpass"})
    log_url = urljoin(base, "/vulnapp/logs/security.log")
    r = req("GET", log_url)

    if r and r.status_code == 200:
        body = r.text.lower()

        if "login" not in body and "fail" not in body:
            return result(
                "WEB-A09-001",
                "A09:2025 Logging & Alerting Failures",
                "로그인 실패 로그 미기록",
                "low",
                "로그 파일에서 로그인 실패 흔적 미확인",
                "로그인 실패 이벤트 기록 및 알림 정책 적용"
            )

    return None


def check_admin_logging(base):
    req("GET", urljoin(base, "/vulnapp/admin.jsp"))
    log_url = urljoin(base, "/vulnapp/logs/security.log")
    r = req("GET", log_url)

    if r and r.status_code == 200:
        body = r.text.lower()

        if "admin" not in body:
            return result(
                "WEB-A09-002",
                "A09:2025 Logging & Alerting Failures",
                "관리자 행위 로그 미기록",
                "low",
                "관리자 페이지 접근 후 로그에서 admin 이벤트 미확인",
                "관리자 기능 접근 및 변경 행위 감사 로그 기록"
            )

    return None


# A10 Mishandling of Exceptional Conditions

def check_stacktrace(base):
    test_urls = [
        urljoin(base, "/vulnapp/error.jsp"),
        urljoin(base, "/vulnapp/login.jsp?id='"),
        urljoin(base, "/vulnapp/search.jsp?q=%")
    ]

    keywords = [
        "exception",
        "stacktrace",
        "traceback",
        "java.lang.",
        "org.apache.",
        "sqlsyntaxerrorexception"
    ]

    for url in test_urls:
        r = req("GET", url)

        if r:
            body = r.text.lower()

            if any(k in body for k in keywords):
                return result(
                    "WEB-A10-001",
                    "A10:2025 Mishandling of Exceptional Conditions",
                    "Stack Trace 노출",
                    "low",
                    f"예외 정보 노출 URL: {url}",
                    "커스텀 에러 페이지 적용 및 상세 예외 메시지 숨김"
                )

    return None


def check_file_read(base):
    url = urljoin(base, "/vulnapp/download.jsp")
    payload = "../../../../etc/passwd"
    r = req("GET", url, params={"filename": payload})

    if not r:
        return None

    indicators = [
        "root:x:",
        "/bin/bash",
        "/bin/sh",
        "daemon:x:",
        "nobody:x:"
    ]

    body = r.text[:3000].lower()
    hits = [i for i in indicators if i in body]

    if hits:
        return result(
            "WEB-A10-002",
            "A10:2025 Mishandling of Exceptional Conditions",
            "임의 파일 읽기",
            "high",
            f"download.jsp filename 조작으로 시스템 파일 내용 탐지: {hits}",
            "다운로드 대상 파일을 허용 목록으로 제한하고 경로 정규화 및 상위 디렉터리 접근 차단"
        )

    return None


def scan(base_url, output, run_sqlmap):
    base_url = normalize_base_url(base_url)
    output = next_output_path(output)

    checks = [
        check_admin_page(base_url),
        check_idor(base_url),

        check_security_headers(base_url),
        check_server_info(base_url),
        check_tomcat_manager(base_url),

        check_log4j(base_url),
        check_old_jquery(base_url),

        check_https(base_url),
        check_cookie_flags(base_url),

        check_sqli(base_url, run_sqlmap),
        check_reflected_xss(base_url),
        check_stored_xss(base_url),
        check_command_injection(base_url),

        check_rate_limit(base_url),
        check_debug_mode(base_url),

        check_account_lockout(base_url),
        check_weak_password(base_url),
        check_jwt_none(base_url),

        check_webshell_upload(base_url),

        check_login_logging(base_url),
        check_admin_logging(base_url),

        check_stacktrace(base_url),
        check_file_read(base_url)
    ]

    findings = [c for c in checks if c is not None]
    results = add_result_ids(findings)

    report = {
        "scan_id": make_scan_id(),
        "target": base_url.rstrip("/"),
        "scanner": "signature-based",
        "generated_at": now_utc(),
        "summary": build_summary(results),
        "results": results
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
    parser.add_argument("--sqlmap", action="store_true")

    args = parser.parse_args()

    scan(args.url, args.output, args.sqlmap)
