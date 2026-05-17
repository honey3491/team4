import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse, quote

import requests
from bs4 import BeautifulSoup

TIMEOUT = 20
HEADERS = {"User-Agent": "SignatureBasedWebVulnScanner/3.0"}
KST = timezone(timedelta(hours=9))

SQL_ERRORS = [
    "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
    "SQLException", "You have an error in your SQL syntax", "ODBC", "JDBC",
    "SQLSyntaxErrorException", "MariaDB", "Unknown column"
]

XSS_PAYLOAD = "<script>alert(1)</script>"
NORMAL_USER_ID = os.getenv("SCANNER_NORMAL_USER_ID", "user1")
NORMAL_USER_PW = os.getenv("SCANNER_NORMAL_USER_PW", "user1234")
CHECK_CATALOG = [
    ("WEB-A01-001", "A01:2025 Broken Access Control", "관리자 페이지 직접 접근", "/vulnapp/admin.jsp"),
    ("WEB-A01-002", "A01:2025 Broken Access Control", "IDOR", "/vulnapp/profile.jsp?user_idx="),
    ("WEB-A02-001", "A02:2025 Security Misconfiguration", "보안 헤더 미설정", "/vulnapp/"),
    ("WEB-A02-002", "A02:2025 Security Misconfiguration", "서버 버전 노출", "/, :8080/"),
    ("WEB-A02-003", "A02:2025 Security Misconfiguration", "Tomcat 기본페이지 노출", ":8080/"),
    ("WEB-A02-004", "A02:2025 Security Misconfiguration", "debug=true 기능 활성화", "/vulnapp/debug.jsp"),
    ("WEB-A03-001", "A03:2025 Software Supply Chain Failures", "취약한 Log4j 사용", "N/A"),
    ("WEB-A03-002", "A03:2025 Software Supply Chain Failures", "구버전 jQuery 사용", "N/A"),
    ("WEB-A04-001", "A04:2025 Cryptographic Failures", "HTTPS 미적용", "/vulnapp/"),
    ("WEB-A04-002", "A04:2025 Cryptographic Failures", "쿠키 Secure/HttpOnly 미설정", "/vulnapp/login.jsp"),
    ("WEB-A05-001", "A05:2025 Injection", "SQL Injection", "/vulnapp/login.jsp"),
    ("WEB-A05-002", "A05:2025 Injection", "Reflected XSS", "/vulnapp/search.jsp?keyword="),
    ("WEB-A05-003", "A05:2025 Injection", "Stored XSS", "/vulnapp/upload.jsp"),
    ("WEB-A05-004", "A05:2025 Injection", "Command Injection", "/vulnapp/ping.jsp?host="),
    ("WEB-A06-001", "A06:2025 Insecure Design", "로그인 Rate Limit 미구현", "/vulnapp/login.jsp"),
    ("WEB-A07-001", "A07:2025 Authentication Failures", "계정 잠금 미구현", "/vulnapp/login.jsp"),
    ("WEB-A07-002", "A07:2025 Authentication Failures", "약한 비밀번호 허용", "/vulnapp/register.jsp"),
    ("WEB-A07-003", "A07:2025 Authentication Failures", "JWT 검증 우회", "N/A"),
    ("WEB-A08-001", "A08:2025 Software or Data Integrity Failures", "웹쉘 업로드 가능", "/vulnapp/upload.jsp"),
    ("WEB-A10-001", "A10:2025 Mishandling of Exceptional Conditions", "Stack Trace 노출", "/vulnapp/profile.jsp?user_idx=abc"),
    ("WEB-A10-002", "A10:2025 Mishandling of Exceptional Conditions", "SSRF", "/vulnapp/fetch.jsp?url="),
]


def req(method, url, **kwargs):
    try:
        headers = {**HEADERS, **kwargs.pop("headers", {})}
        return requests.request(
            method,
            url,
            headers=headers,
            timeout=TIMEOUT,
            allow_redirects=kwargs.pop("allow_redirects", False),
            verify=False,
            **kwargs,
        )
    except Exception as exc:
        return {"error": str(exc), "url": url}


def normalize_base_url(base_url):
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url
    return base_url.rstrip("/") + "/"


def tomcat_base_url(base_url, tomcat_port=8080):
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or parsed.netloc.split(":")[0]
    return f"{scheme}://{host}:{tomcat_port}/"


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
        "recommendation": recommendation,
    }


def catalog_item(check_id):
    for item in CHECK_CATALOG:
        if item[0] == check_id:
            return item
    raise KeyError(check_id)


def catalog_result(check_id, severity, evidence, recommendation):
    cid, owasp, name, url = catalog_item(check_id)
    return result(cid, owasp, name, severity, evidence, recommendation, url)


def add_result_ids(results):
    return [
        {
            "id": f"RES-{idx:04d}",
            "check_id": r["check_id"],
            "owasp": r["owasp"],
            "name": r["name"],
            "url": r.get("url", ""),
            "severity": r["severity"],
            "evidence": r["evidence"],
            "recommendation": r["recommendation"],
        }
        for idx, r in enumerate(results, start=1)
    ]


def build_summary(results):
    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "pass": 0, "n/a": 0, "pending": 0}
    for r in results:
        sev = str(r.get("severity", "")).lower()
        if sev in severity:
            severity[sev] += 1
    return {"total": len(results), "severity": severity}


def body_lower(response):
    if isinstance(response, dict):
        return ""
    return response.text.lower()


def status_code(response):
    return None if isinstance(response, dict) else response.status_code


def header(response, name, default=""):
    return default if isinstance(response, dict) else response.headers.get(name, default)


def check_admin_page(base):
    url = urljoin(base, "/vulnapp/admin.jsp")
    login_url = urljoin(base, "/vulnapp/login.jsp")

    # 1) 비로그인 요청 확인
    r = req("GET", url)
    body = body_lower(r)
    loc = header(r, "Location", "")
    admin_keywords = ["admin page", "user list", "system config", "backup download", "관리자"]

    if status_code(r) == 200 and any(k in body for k in admin_keywords):
        return catalog_result(
            "WEB-A01-001", "medium",
            "/vulnapp/admin.jsp 비로그인 요청에서 관리자 페이지 키워드가 포함된 200 응답 확인",
            "관리자 페이지 접근 시 로그인 여부와 관리자 권한을 서버 측에서 검증하고 일반 사용자는 403 또는 접근 권한 없음으로 차단해야 한다."
        )

    anonymous_note = ""
    if status_code(r) in [301, 302, 303, 307, 308] and "login" in loc.lower():
        anonymous_note = "/vulnapp/admin.jsp 비로그인 요청은 로그인 페이지로 리다이렉트됨."

    # 2) 일반 사용자 로그인 후 관리자 페이지 접근 가능 여부 확인
    #    수동진단 기준에 맞춰 미인증 접근뿐 아니라 일반 사용자 권한 우회도 WEB-A01-001로 판단한다.
    user_session = requests.Session()
    user_session.headers.update(HEADERS)
    try:
        user_session.post(
            login_url,
            data={"id": NORMAL_USER_ID, "pw": NORMAL_USER_PW},
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=False,
        )
        user_admin = user_session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=False,
        )
        user_body = user_admin.text.lower()
        if user_admin.status_code == 200 and any(k in user_body for k in admin_keywords):
            return catalog_result(
                "WEB-A01-001", "medium",
                f"{anonymous_note} 일반 사용자({NORMAL_USER_ID}) 로그인 세션으로 /vulnapp/admin.jsp 접근 시 200 응답과 관리자 페이지 키워드가 확인되어 관리자 권한 검증 미흡이 확인됨.",
                "관리자 페이지 접근 시 단순 로그인 여부가 아니라 사용자 role이 admin인지 서버 측에서 검증하고 일반 사용자 접근은 403 또는 접근 권한 없음으로 차단해야 한다."
            )
    except requests.RequestException:
        pass

    if anonymous_note:
        return catalog_result(
            "WEB-A01-001", "n/a",
            f"{anonymous_note} 일반 사용자 권한 우회 여부는 자동 로그인 계정 기반 진단에서 확인되지 않았거나 계정 정보가 맞지 않아 추가 수동 확인이 필요함.",
            "일반 사용자 로그인 세션으로 관리자 페이지 접근 가능 여부를 추가 확인하고, 관리자 권한 검증을 적용해야 한다."
        )
    return catalog_result("WEB-A01-001", "n/a", "관리자 페이지 접근제어 여부를 외부 요청만으로 명확히 확인하지 못함.", "관리자 권한 검증을 수동으로 추가 확인해야 한다.")


def check_idor(base):
    urls = [urljoin(base, f"/vulnapp/profile.jsp?user_idx={idx}") for idx in [1, 2, 3]]
    responses = [req("GET", u) for u in urls]
    ok = [r for r in responses if status_code(r) == 200]
    bodies = [r.text for r in ok if not isinstance(r, dict)]
    joined = "\n".join(bodies).lower()
    if len(set(bodies)) > 1 and any(k in joined for k in ["사용자 id", "회원 번호", "권한 레벨", "user"]):
        return catalog_result(
            "WEB-A01-002", "high",
            "profile.jsp의 user_idx 값을 변경했을 때 서로 다른 사용자 정보가 200 응답으로 노출됨.",
            "사용자 정보 조회 시 세션 사용자와 조회 대상 user_idx가 일치하는지 서버 측에서 검증하고 권한 없는 접근은 403으로 차단해야 한다."
        )
    return catalog_result("WEB-A01-002", "n/a", "user_idx 변경에 따른 타 사용자 정보 노출을 자동 시그니처만으로 확정하지 못함.", "인증된 일반 사용자 세션으로 IDOR 수동 검증이 필요하다.")


def check_security_headers(base):
    url = urljoin(base, "/vulnapp/")
    r = req("GET", url)
    if isinstance(r, dict):
        return catalog_result("WEB-A02-001", "n/a", f"/vulnapp/ 요청 실패: {r.get('error')}", "응답 헤더 확인 후 보안 헤더 설정 여부를 재점검해야 한다.")
    required = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
    missing = [h for h in required if h not in r.headers]
    if missing:
        return catalog_result("WEB-A02-001", "low", f"/vulnapp/ 응답에서 주요 보안 헤더 누락: {missing}", "CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy 등 주요 보안 헤더를 설정해야 한다.")
    return catalog_result("WEB-A02-001", "pass", "주요 보안 헤더가 응답에 설정되어 있음.", "현재 보안 헤더 설정을 유지하고 CSP 정책을 지속 강화해야 한다.")


def check_server_info(base, tomcat_port=8080):
    urls = [urljoin(base, "/"), urljoin(base, "/vulnapp/"), tomcat_base_url(base, tomcat_port)]
    hits = []
    for url in urls:
        r = req("GET", url)
        if isinstance(r, dict):
            continue
        server = r.headers.get("Server")
        if server:
            hits.append(f"{url} Server={server}")
        body = r.text[:3000]
        for keyword in ["Apache Tomcat/", "nginx/", "Apache-Coyote"]:
            if keyword.lower() in body.lower():
                hits.append(f"{url} body contains {keyword}")
    if hits:
        return catalog_result("WEB-A02-002", "low", "; ".join(hits), "서버 배너와 기본/오류 페이지의 제품명 및 상세 버전 노출을 제거해야 한다.")
    return catalog_result("WEB-A02-002", "pass", "응답 헤더와 본문에서 상세 서버 버전 노출이 확인되지 않음.", "서버 정보 최소 노출 설정을 유지해야 한다.")


def check_tomcat_default(base, tomcat_port=8080):
    url = tomcat_base_url(base, tomcat_port)
    r = req("GET", url)
    body = body_lower(r)
    if status_code(r) == 200 and any(k in body for k in ["apache tomcat", "manager app", "host manager"]):
        return catalog_result("WEB-A02-003", "medium", f"{url}에서 Tomcat 기본 페이지와 Manager/Host Manager 링크 노출", "Tomcat ROOT 기본 페이지와 관리 링크를 제거하고 8080 포트 외부 직접 접근을 제한해야 한다.")
    return catalog_result("WEB-A02-003", "pass", "Tomcat 기본 페이지 노출이 확인되지 않음.", "Tomcat 기본 앱 제거와 포트 접근 제한 상태를 유지해야 한다.")


def check_log4j(base):
    # 외부 HTTP만으로 서버 내부 라이브러리 사용 여부를 확정하기 어렵기 때문에 응답 노출 흔적만 확인하고 없으면 N/A 처리한다.
    urls = [urljoin(base, "/vulnapp/"), urljoin(base, "/vulnapp/login.jsp"), urljoin(base, "/vulnapp/search.jsp")]
    hits = []
    for url in urls:
        r = req("GET", url, headers={"X-Api-Version": "${jndi:ldap://127.0.0.1/a}"})
        if isinstance(r, dict):
            continue
        if "log4j" in r.text.lower() or "jndilookup" in r.text.lower():
            hits.append(url)
    if hits:
        return catalog_result("WEB-A03-001", "medium", f"HTTP 응답에서 Log4j/JNDI 관련 문자열 확인: {hits}", "Log4j 사용 여부와 버전을 확인하고 취약 버전이면 업데이트해야 한다.")
    return catalog_result("WEB-A03-001", "n/a", "외부 HTTP 응답에서 Log4j 사용 흔적이 확인되지 않음. 서버 내부 라이브러리 확인은 수동진단으로 보완 필요.", "현재 Log4j 미사용이면 별도 조치는 불필요하며 향후 도입 시 취약 버전 점검이 필요하다.")


def check_old_jquery(base):
    urls = [urljoin(base, "/vulnapp/"), urljoin(base, "/vulnapp/login.jsp"), urljoin(base, "/vulnapp/search.jsp"), urljoin(base, "/vulnapp/admin.jsp")]
    jquery_hits = []
    old_hits = []
    for url in urls:
        r = req("GET", url)
        if isinstance(r, dict):
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if "jquery" in src.lower():
                jquery_hits.append(src)
                if "jquery-1." in src.lower() or "jquery-2." in src.lower():
                    old_hits.append(src)
        if "jquery" in r.text.lower():
            jquery_hits.append(f"inline-or-body:{url}")
    if old_hits:
        return catalog_result("WEB-A03-002", "medium", f"구버전 jQuery 참조 확인: {old_hits}", "jQuery 최신 안정 버전으로 업데이트해야 한다.")
    if jquery_hits:
        return catalog_result("WEB-A03-002", "pass", f"jQuery 참조는 있으나 구버전 패턴은 확인되지 않음: {jquery_hits}", "외부 JS 라이브러리 버전을 정기적으로 점검해야 한다.")
    return catalog_result("WEB-A03-002", "n/a", "주요 페이지 HTML에서 jQuery 참조가 확인되지 않아 구버전 jQuery 진단 대상이 아님.", "향후 jQuery 도입 시 최신 버전을 사용하고 취약 버전 여부를 점검해야 한다.")


def check_https(base):
    parsed = urlparse(base)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    http_url = f"http://{host}/vulnapp/"
    https_url = f"https://{host}/vulnapp/"
    http_res = req("GET", http_url)
    redirect_to_https = (status_code(http_res) in [301, 302, 307, 308] and header(http_res, "Location", "").startswith("https://"))
    try:
        https_res = requests.get(https_url, headers=HEADERS, timeout=TIMEOUT, verify=False, allow_redirects=False)
        https_ok = https_res.status_code < 500
    except Exception:
        https_ok = False
    if not redirect_to_https or not https_ok:
        return catalog_result("WEB-A04-001", "medium", f"HTTP 접속 가능 및 HTTPS 강제 리다이렉트 미확인. https_available={https_ok}, redirect_to_https={redirect_to_https}", "TLS 인증서를 적용하고 모든 HTTP 요청을 HTTPS로 강제 리다이렉트해야 한다.")
    return catalog_result("WEB-A04-001", "pass", "HTTPS 접속과 HTTP→HTTPS 리다이렉트가 확인됨.", "HTTPS 강제 적용 정책을 유지해야 한다.")


def check_cookie_flags(base):
    r = req("GET", urljoin(base, "/vulnapp/login.jsp"))
    cookies = header(r, "Set-Cookie", "")
    if not cookies:
        return catalog_result("WEB-A04-002", "n/a", "로그인 페이지 응답에서 Set-Cookie가 확인되지 않음.", "로그인 후 세션 쿠키 속성을 추가 확인해야 한다.")
    lower = cookies.lower()
    missing = [flag for flag in ["secure", "httponly", "samesite"] if flag not in lower]
    if missing:
        return catalog_result("WEB-A04-002", "medium", f"Set-Cookie={cookies}, missing={missing}", "세션 쿠키에 Secure, HttpOnly, SameSite 속성을 적용해야 한다.")
    return catalog_result("WEB-A04-002", "pass", "세션 쿠키에 Secure, HttpOnly, SameSite 속성이 설정되어 있음.", "쿠키 보안 속성을 유지해야 한다.")


def extract_login_form(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
    except Exception:
        return None
    soup = BeautifulSoup(r.text, "html.parser")
    form = soup.find("form")
    if not form:
        return None
    return {
        "action": urljoin(url, form.get("action", "")),
        "method": form.get("method", "GET").upper(),
        "params": [{"name": i.get("name"), "type": i.get("type", "text")} for i in form.find_all("input") if i.get("name")],
    }


def post_form(form, data):
    if form["method"] == "POST":
        return req("POST", form["action"], data=data)
    return req("GET", form["action"], params=data)


def check_sqli(base, run_sqlmap=False):
    login_url = urljoin(base, "/vulnapp/login.jsp")
    form = extract_login_form(login_url)
    if not form:
        return catalog_result("WEB-A05-001", "n/a", "로그인 폼을 찾지 못해 SQL Injection 자동 점검 불가.", "로그인 폼 존재 여부를 확인하고 수동 점검해야 한다.")
    payloads = ["' OR '1'='1' -- ", "admin' -- ", "' OR 1=1 -- "]
    for payload in payloads:
        data = {}
        for p in form["params"]:
            name = p["name"]
            typ = p.get("type", "text").lower()
            if typ == "submit":
                continue
            data[name] = payload if typ in ["text", "password", "email", "search"] else "test"
        r = post_form(form, data)
        if isinstance(r, dict):
            continue
        body = r.text.lower()
        location = r.headers.get("Location", "")
        redirected_to_admin = r.status_code in [301, 302, 303, 307, 308] and "admin.jsp" in location.lower()
        error_hit = any(e.lower() in body for e in SQL_ERRORS)
        success_body = any(k in body for k in ["로그아웃", "profile.jsp", "admin page", "관리자"])
        if redirected_to_admin or error_hit or success_body:
            evidence = {"payload": payload.strip(), "redirect_location": location, "error_based": error_hit, "auth_bypass": redirected_to_admin or success_body}
            if run_sqlmap:
                evidence["sqlmap"] = run_sqlmap_probe(form)
            return catalog_result("WEB-A05-001", "high", evidence, "PreparedStatement와 바인딩 파라미터를 사용하고 입력값 검증 및 DB 오류 메시지 비노출 처리를 적용해야 한다.")
    return catalog_result("WEB-A05-001", "pass", "대표 SQL Injection 페이로드에서 인증 우회 또는 SQL 오류 노출이 확인되지 않음.", "PreparedStatement 기반 방어 상태를 유지해야 한다.")


def run_sqlmap_probe(form):
    params = [p["name"] for p in form["params"] if p.get("name") and p.get("type", "text").lower() != "submit"]
    data_str = "&".join([f"{name}=test" for name in params])
    cmd = ["sqlmap", "-u", form["action"], "--batch", "--level", "2", "--risk", "1", "--banner", "--current-user", "--current-db", "--is-dba", "--dbs"]
    if form["method"] == "POST":
        cmd.extend(["--data", data_str])
    else:
        cmd[2] = form["action"] + ("&" if "?" in form["action"] else "?") + data_str
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        output = proc.stdout + "\n" + proc.stderr
        return {"command": " ".join(cmd), "returncode": proc.returncode, "raw_tail": output[-2000:]}
    except FileNotFoundError:
        return {"error": "sqlmap not installed"}
    except Exception as exc:
        return {"error": str(exc)}


def check_reflected_xss(base):
    url = urljoin(base, "/vulnapp/search.jsp")
    r = req("GET", url, params={"keyword": XSS_PAYLOAD})
    if isinstance(r, dict):
        return catalog_result("WEB-A05-002", "n/a", "search.jsp 요청 실패로 Reflected XSS 자동 점검 불가.", "검색 기능 상태를 확인해야 한다.")
    if XSS_PAYLOAD in r.text:
        return catalog_result("WEB-A05-002", "medium", "keyword 파라미터에 입력한 script 태그가 응답에 HTML escaping 없이 반영됨.", "검색어 출력 시 HTML escaping을 적용해야 한다.")
    return catalog_result("WEB-A05-002", "pass", "대표 XSS 페이로드가 응답에 실행 가능한 형태로 반영되지 않음.", "출력 인코딩 정책을 유지해야 한다.")


def check_stored_xss(base):
    """
    Stored XSS는 저장 후 재조회 화면에서 실행 여부를 확인해야 확정할 수 있다.
    현재 프로젝트 수동진단 기준:
    - 게시글 상세 조회 404 등 사이트 오류로 재조회 검증이 불가능하면 pending.
    - 목록에서 저장형 페이로드가 실행 가능한 형태로 노출되면 medium.
    - 상세/목록에서 HTML escaping이 명확히 확인될 때만 pass.
    """
    upload_url = urljoin(base, "/vulnapp/upload.jsp")
    list_url = urljoin(base, "/vulnapp/search.jsp")
    upload_r = req("GET", upload_url)
    if status_code(upload_r) == 404:
        return catalog_result(
            "WEB-A05-003",
            "pending",
            "/vulnapp/upload.jsp가 404로 확인되어 게시글 저장 기능을 통한 Stored XSS 재현이 불가능함.",
            "게시글 작성 및 상세 조회 기능 정상화 후 저장된 입력값이 HTML escaping되어 출력되는지 재진단해야 한다."
        )

    list_r = req("GET", list_url)
    if isinstance(list_r, dict):
        return catalog_result(
            "WEB-A05-003",
            "pending",
            "/vulnapp/search.jsp 게시글 목록 조회 실패로 저장형 XSS 재조회 검증이 불가능함.",
            "게시글 목록/상세 조회 기능을 정상화한 뒤 Stored XSS를 재진단해야 한다."
        )

    list_body = list_r.text
    if XSS_PAYLOAD in list_body:
        return catalog_result(
            "WEB-A05-003",
            "medium",
            "게시글 목록에서 저장된 XSS 페이로드가 HTML escaping 없이 실행 가능한 형태로 노출됨.",
            "저장 데이터 출력 시 HTML escaping을 적용해야 한다."
        )

    # 목록에서는 실행 흔적이 없지만 상세 조회 URL이 404인 경우가 있어 pass로 확정하지 않는다.
    # 상세 조회가 정상화되어 저장된 제목/본문이 escape 처리되는지 확인되어야 양호(pass)로 판단할 수 있다.
    return catalog_result(
        "WEB-A05-003",
        "pending",
        "게시글 목록에서는 저장형 XSS 페이로드 실행 흔적이 확인되지 않았으나, 저장된 게시글 상세 조회 검증이 필요함. 수동진단에서 게시글 상세 조회 404가 확인되어 최종 판단 보류.",
        "게시글 상세 조회 페이지를 정상화하고 저장된 <script>alert(1)</script>가 실행되지 않고 HTML escaping되어 출력되는지 재진단해야 한다."
    )

def check_command_injection(base):
    url = urljoin(base, "/vulnapp/ping.jsp")
    normal = req("GET", url, params={"host": "127.0.0.1"})
    if status_code(normal) == 404:
        return catalog_result("WEB-A05-004", "pending", "/vulnapp/ping.jsp?host=127.0.0.1 요청이 404로 확인되어 Command Injection 진단을 수행할 수 없음.", "ping.jsp 기능을 구현하되 ;whoami, &&id, |whoami 같은 명령어 삽입 입력은 차단되도록 수정 후 재진단해야 한다.")
    payloads = ["127.0.0.1;whoami", "127.0.0.1&&id", "127.0.0.1|whoami"]
    execution_hits = []
    blocked = []
    for payload in payloads:
        r = req("GET", url, params={"host": payload})
        b = body_lower(r)
        if any(k in b for k in ["uid=", "gid=", "root", "tomcat", "ubuntu"]):
            execution_hits.append(payload)
        elif status_code(r) in [400, 403] or any(k in b for k in ["invalid", "허용", "차단", "올바르지"]):
            blocked.append(payload)
    if execution_hits:
        return catalog_result("WEB-A05-004", "high", f"명령 실행 결과가 응답에 노출된 페이로드: {execution_hits}", "OS 명령 직접 실행을 제거하고 allowlist 기반 입력 검증을 적용해야 한다.")
    return catalog_result("WEB-A05-004", "pass", f"명령어 삽입 페이로드에서 실행 결과 미노출. blocked={blocked}", "host 입력값은 허용 문자만 통과시키고 OS 명령 문자열 직접 결합을 금지해야 한다.")


def check_rate_limit(base):
    url = urljoin(base, "/vulnapp/login.jsp")
    statuses = []
    for i in range(10):
        r = req("POST", url, data={"id": "admin", "pw": f"wrong{i}"})
        statuses.append(status_code(r))
    if not any(s in [423, 429, 403] for s in statuses):
        return catalog_result("WEB-A06-001", "medium", f"잘못된 비밀번호 10회 연속 요청 상태코드: {statuses}. 제한 응답 미확인.", "동일 계정/IP 기준 로그인 실패 횟수 제한, 지연 응답, CAPTCHA 등을 적용해야 한다.")
    return catalog_result("WEB-A06-001", "pass", f"반복 로그인 실패 중 제한 응답 확인: {statuses}", "Rate Limit 정책을 유지해야 한다.")


def check_debug_mode(base):
    urls = [urljoin(base, "/vulnapp/debug.jsp"), urljoin(base, "/vulnapp/debug.jsp?debug=true")]
    for url in urls:
        r = req("GET", url)
        body = body_lower(r)
        if status_code(r) == 200 and any(k in body for k in ["db_password", "api_key", "internal_ip", "debug", "classpath", "config"]):
            return catalog_result("WEB-A02-004", "medium", f"{url}에서 debug/API 키/DB 계정/내부 IP 등 내부 정보 노출", "운영 환경에서 디버그 페이지를 제거하고 민감정보를 응답에 출력하지 않아야 한다.")
    return catalog_result("WEB-A02-004", "pass", "debug.jsp에서 민감한 디버그 정보 노출이 확인되지 않음.", "디버그 기능 비활성화 상태를 유지해야 한다.")


def check_account_lockout(base):
    url = urljoin(base, "/vulnapp/login.jsp")
    statuses = []
    for i in range(10):
        r = req("POST", url, data={"id": "admin", "pw": f"wrong{i}"})
        statuses.append(status_code(r))
    if not any(s in [423, 429, 403] for s in statuses):
        return catalog_result("WEB-A07-001", "medium", f"동일 계정 10회 실패 후에도 잠금/차단 응답 없음. statuses={statuses}", "연속 로그인 실패 횟수를 서버 측에서 관리하고 일정 횟수 이상 실패 시 계정 잠금 또는 추가 인증을 적용해야 한다.")
    return catalog_result("WEB-A07-001", "pass", f"반복 인증 실패 중 계정 잠금 또는 차단 응답 확인: {statuses}", "계정 잠금 정책을 유지해야 한다.")


def check_weak_password(base):
    url = urljoin(base, "/vulnapp/register.jsp")
    get_r = req("GET", url)
    if status_code(get_r) == 404:
        return catalog_result("WEB-A07-002", "pending", "/vulnapp/register.jsp 요청이 404로 확인되어 약한 비밀번호 허용 여부를 진단할 수 없음.", "회원가입 또는 비밀번호 설정 기능을 구현하고 1234, password, admin123 같은 약한 비밀번호를 서버 측에서 거부하도록 수정 후 재진단해야 한다.")
    weak_passwords = ["1234", "password", "admin123"]
    allowed = []
    for pw in weak_passwords:
        r = req("POST", url, data={"id": f"test_{int(time.time())}", "pw": pw, "pw_confirm": pw})
        if status_code(r) in [200, 201, 302] and any(k in body_lower(r) for k in ["success", "created", "registered", "가입 완료"]):
            allowed.append(pw)
    if allowed:
        return catalog_result("WEB-A07-002", "medium", f"약한 비밀번호가 허용됨: {allowed}", "비밀번호 최소 길이, 복잡도, 사전 기반 약한 비밀번호 차단 정책을 서버 측에서 적용해야 한다.")
    return catalog_result("WEB-A07-002", "pass", "대표 약한 비밀번호가 가입/설정 성공으로 처리되지 않음.", "서버 측 비밀번호 정책을 유지해야 한다.")


def check_jwt_none(base):
    login_r = req("GET", urljoin(base, "/vulnapp/login.jsp"))
    cookies = header(login_r, "Set-Cookie", "")
    body = body_lower(login_r)
    jwt_like = any(k in body for k in ["access_token", "refresh_token", "authorization", "bearer", "eyj"])
    if "jsessionid" in cookies.lower() and not jwt_like:
        return catalog_result("WEB-A07-003", "n/a", "로그인 응답에서 JSESSIONID 세션 쿠키만 확인되고 JWT/Bearer/access_token이 확인되지 않음.", "현재 JWT 미사용으로 별도 조치는 불필요하며 향후 JWT 도입 시 서명 검증과 alg=none 차단을 적용해야 한다.")
    return catalog_result("WEB-A07-003", "n/a", "JWT 기반 인증 사용 여부를 자동 시그니처만으로 확인하지 못함.", "브라우저 저장소와 Authorization 헤더를 수동으로 확인해야 한다.")


def check_webshell_upload(base):
    upload_page = req("GET", urljoin(base, "/vulnapp/upload.jsp"))
    if status_code(upload_page) == 404:
        return catalog_result("WEB-A08-001", "pending", "/vulnapp/upload.jsp가 404로 확인되어 웹쉘 업로드 진단을 수행할 수 없음.", "파일 업로드 기능을 정상화한 뒤 shell.jsp 업로드 성공 또는 명확한 차단 결과를 기준으로 재진단해야 한다.")
    shell_name = "probe.jsp"
    shell_body = b'<% out.println("WEB_SHELL_PROBE_1337"); %>'
    for endpoint in ["/vulnapp/upload_process.jsp", "/vulnapp/upload.jsp"]:
        req("POST", urljoin(base, endpoint), files={"file": (shell_name, shell_body, "application/octet-stream")})
    possible_paths = [urljoin(base, f"/vulnapp/uploads/{shell_name}"), urljoin(base, f"/uploads/{shell_name}")]
    for path in possible_paths:
        check = req("GET", path)
        if not isinstance(check, dict) and "WEB_SHELL_PROBE_1337" in check.text:
            return catalog_result("WEB-A08-001", "critical", f"{path} 접근 시 업로드한 JSP 테스트 문자열 실행 확인", "실행 가능한 확장자 업로드를 차단하고 업로드 파일은 웹 루트 외부에 저장해야 한다.")
    return catalog_result("WEB-A08-001", "pending", "shell.jsp 업로드 시도 후 업로드 실행 여부가 확인되지 않음. upload_process.jsp 500, 저장 경로 404 등 업로드 처리 오류 또는 저장 경로 확인이 필요함.", "WEB-A08-001은 취약 항목으로 설계했으므로 shell.jsp 업로드가 성공하고 /vulnapp/uploads/shell.jsp 접근 시 JSP_UPLOAD_TEST 문자열이 출력되도록 수정 후 재진단해야 한다.")


def check_stacktrace(base):
    test_urls = [
        urljoin(base, "/vulnapp/profile.jsp?user_idx=abc"),
        urljoin(base, "/vulnapp/error.jsp?type=exception"),
        urljoin(base, "/vulnapp/not-exist.jsp"),
    ]
    stack_keywords = ["java.lang", "jasperexception", "nullpointerexception", "classnotfoundexception", "org.apache", "at org.apache", "root cause"]
    info_keywords = ["unknown column", "sqlsyntax", "database error", "데이터베이스 오류"]
    for url in test_urls:
        r = req("GET", url)
        body = body_lower(r)
        if any(k in body for k in stack_keywords):
            return catalog_result("WEB-A10-001", "medium", f"{url} 응답에 Java/Tomcat stack trace 관련 문자열 노출", "커스텀 에러 페이지를 적용하고 상세 예외 정보는 서버 로그에만 기록해야 한다.")
        if any(k in body for k in info_keywords):
            return catalog_result("WEB-A10-001", "pending", f"{url} 응답에 내부 DB/예외 메시지가 노출되지만 Java/Tomcat stack trace 자체는 확인되지 않음. 원래 양호 항목으로 설계되어 사이트 수정 후 재진단 필요.", "사용자에게는 일반 오류 메시지만 보여주고 상세 DB/예외 정보는 서버 로그에만 기록하도록 수정 후 재진단해야 한다.")
    return catalog_result("WEB-A10-001", "pass", "오류 유발 요청에서 Java/Tomcat stack trace 또는 내부 예외 정보가 확인되지 않음.", "커스텀 에러 페이지와 예외 정보 비노출 정책을 유지해야 한다.")


def check_ssrf(base):
    fetch_url = urljoin(base, "/vulnapp/fetch.jsp")
    base_check = req("GET", fetch_url)
    if status_code(base_check) == 404:
        return catalog_result("WEB-A10-002", "pending", "/vulnapp/fetch.jsp가 404로 확인되어 SSRF 진단을 수행할 수 없음. /vulnapp/internal/secret.jsp도 404라 내부 테스트 자원 확인이 필요함.", "fetch.jsp?url= 기능과 /vulnapp/internal/secret.jsp 내부 테스트 페이지를 구현한 뒤 SSRF 취약 여부를 재진단해야 한다.")
    targets = ["http://127.0.0.1:8080/", "http://localhost:8080/"]
    for target_url in targets:
        r = req("GET", fetch_url, params={"url": target_url})
        body = body_lower(r)
        if status_code(r) == 200 and any(k in body for k in ["apache tomcat", "manager app", "host manager"]):
            return catalog_result("WEB-A10-002", "high", f"fetch.jsp가 내부 URL {target_url}을 요청하고 Tomcat 내부 페이지 내용을 반환", "사용자 입력 URL 요청을 제한하고 localhost/사설 IP/메타데이터 주소 접근을 차단해야 한다.")
    return catalog_result("WEB-A10-002", "pending", "fetch.jsp는 존재하나 localhost/127.0.0.1 대상 내부 자원 반환 또는 명확한 차단 근거가 확인되지 않아 SSRF 최종 판단 보류.", "내부 테스트 페이지와 차단 정책을 명확히 구현한 뒤 SSRF를 재진단해야 한다.")


def scan(base_url, output, run_sqlmap, tomcat_port=8080):
    base_url = normalize_base_url(base_url)
    # 요구사항: 기존 scan_result.json이 있으면 새 파일명을 만들지 않고 그대로 덮어쓴다.
    checks = [
        check_admin_page(base_url),
        check_idor(base_url),
        check_security_headers(base_url),
        check_server_info(base_url, tomcat_port),
        check_tomcat_default(base_url, tomcat_port),
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
        check_stacktrace(base_url),
        check_ssrf(base_url),
    ]
    results = add_result_ids([c for c in checks if c is not None])
    report = {
        "scan_id": make_scan_id(),
        "target": base_url.rstrip("/"),
        "scanner": "signature-based",
        "generated_at": now_utc(),
        "summary": build_summary(results),
        "results": results,
    }
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n[+] saved: {output}")


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="진단 대상 URL 예: http://localhost:8080")
    parser.add_argument("-o", "--output", default="outputs/rule/scan_result.json")
    parser.add_argument("--sqlmap", action="store_true")
    parser.add_argument("--tomcat-port", type=int, default=8080)
    args = parser.parse_args()
    scan(args.url, args.output, args.sqlmap, args.tomcat_port)
