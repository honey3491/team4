import argparse
import json
import re
import socket
import ssl
import time
from datetime import datetime
from urllib.parse import quote, urljoin, urlparse

import requests


class WebVulnScanner:
    def __init__(self, target: str, tomcat_port: int = 8080, timeout: int = 5):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.parsed = urlparse(self.target)
        self.scheme = self.parsed.scheme or "http"
        self.host = self.parsed.hostname
        self.tomcat_port = tomcat_port

        if not self.host:
            raise ValueError("올바른 target URL을 입력하세요. 예: http://EC2_PUBLIC_IP")

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "4AKDA-AutoScanner/1.0"
        })

    def request(self, method: str, url: str, **kwargs):
        try:
            return self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                allow_redirects=kwargs.pop("allow_redirects", True),
                verify=False,
                **kwargs
            )
        except requests.RequestException as e:
            return None

    def result(
        self,
        check_id,
        item,
        category,
        auto_result,
        evidence,
        risk,
        recommendation,
        url=None,
        raw_value=None
    ):
        return {
            "check_id": check_id,
            "category": category,
            "item": item,
            "target": url or self.target,
            "auto_result": auto_result,
            "evidence": evidence,
            "risk": risk,
            "recommendation": recommendation,
            "raw_value": raw_value or "",
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # WEB-001 보안 헤더 미설정
    def check_security_headers(self):
        url = self.target + "/"
        res = self.request("GET", url)

        if res is None:
            return self.result(
                "WEB-001",
                "보안 헤더 미설정",
                "웹서버 설정",
                "N/A",
                "대상 서버에 연결할 수 없어 보안 헤더를 확인하지 못함",
                "N/A",
                "서버 접속 가능 여부를 먼저 확인한다.",
                url
            )

        required_headers = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ]

        missing = []
        present = []

        for h in required_headers:
            if h in res.headers:
                present.append(h)
            else:
                missing.append(h)

        if len(missing) >= 3:
            status = "취약"
            risk = "Medium"
            evidence = f"주요 보안 헤더 누락: {', '.join(missing)}"
        elif len(missing) > 0:
            status = "미흡"
            risk = "Low"
            evidence = f"일부 보안 헤더 누락: {', '.join(missing)}"
        else:
            status = "양호"
            risk = "Low"
            evidence = "주요 보안 헤더가 모두 설정되어 있음"

        return self.result(
            "WEB-001",
            "보안 헤더 미설정",
            "웹서버 설정",
            status,
            evidence,
            risk,
            "Nginx 또는 Tomcat 필터에서 X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy 등을 설정한다.",
            url,
            dict(res.headers)
        )

    # WEB-002 서버 정보 노출
    def check_server_info_exposure(self):
        url = self.target + "/"
        res = self.request("GET", url)

        if res is None:
            return self.result(
                "WEB-002",
                "서버 정보 노출",
                "웹서버 설정",
                "N/A",
                "대상 서버에 연결할 수 없어 서버 정보 노출 여부를 확인하지 못함",
                "N/A",
                "서버 접속 가능 여부를 먼저 확인한다.",
                url
            )

        exposed = []

        server_header = res.headers.get("Server", "")
        x_powered_by = res.headers.get("X-Powered-By", "")

        if server_header:
            exposed.append(f"Server: {server_header}")

        if x_powered_by:
            exposed.append(f"X-Powered-By: {x_powered_by}")

        # 에러 페이지 정보 확인
        error_url = self.target + "/not_exist_4akda_404_test"
        error_res = self.request("GET", error_url)
        error_keywords = []

        if error_res is not None:
            body = error_res.text[:3000]
            for keyword in ["Apache Tomcat", "Tomcat", "nginx", "Apache-Coyote", "version", "Exception"]:
                if keyword.lower() in body.lower():
                    error_keywords.append(keyword)

        if error_keywords:
            exposed.append(f"Error Page Keywords: {', '.join(set(error_keywords))}")

        if exposed:
            status = "취약"
            risk = "Low"
            evidence = "서버 정보가 노출됨: " + " / ".join(exposed)
        else:
            status = "양호"
            risk = "Low"
            evidence = "응답 헤더와 에러 페이지에서 명확한 서버 정보 노출이 확인되지 않음"

        return self.result(
            "WEB-002",
            "서버 정보 노출",
            "웹서버 설정",
            status,
            evidence,
            risk,
            "Server, X-Powered-By 헤더를 숨기고 기본 에러 페이지 대신 커스텀 에러 페이지를 사용한다.",
            url,
            {
                "headers": dict(res.headers),
                "error_keywords": error_keywords
            }
        )

    # WEB-003 SQL Injection
    def check_sql_injection(self):
        payloads = [
            ("admin'--", "test"),
            ("' OR '1'='1' -- ", "test"),
            ("admin", "' OR '1'='1' -- ")
        ]

        success_keywords = [
            "Login Success",
            "Welcome",
            "role=admin",
            "admin"
        ]

        tested = []
        vulnerable_payload = None
        vulnerable_url = None

        for user_id, pw in payloads:
            url = (
                self.target
                + "/vulnapp/login.jsp?id="
                + quote(user_id)
                + "&pw="
                + quote(pw)
            )
            res = self.request("GET", url)
            if res is None:
                continue

            body = res.text
            tested.append({
                "payload_id": user_id,
                "payload_pw": pw,
                "status_code": res.status_code
            })

            if any(keyword.lower() in body.lower() for keyword in success_keywords):
                vulnerable_payload = f"id={user_id}, pw={pw}"
                vulnerable_url = url
                break

        if vulnerable_payload:
            status = "취약"
            risk = "High"
            evidence = f"SQL Injection 페이로드로 로그인 성공 문구가 확인됨: {vulnerable_payload}"
        else:
            status = "양호"
            risk = "Low"
            evidence = "테스트한 SQL Injection 페이로드에서 로그인 우회 징후가 확인되지 않음"

        return self.result(
            "WEB-003",
            "SQL Injection",
            "웹애플리케이션 취약점",
            status,
            evidence,
            risk,
            "PreparedStatement를 사용하고 사용자 입력값을 SQL 쿼리에 직접 연결하지 않는다.",
            vulnerable_url or self.target + "/vulnapp/login.jsp",
            tested
        )

    # WEB-004 XSS
    def check_xss(self):
        payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]

        reflected = []
        tested = []

        for payload in payloads:
            url = self.target + "/vulnapp/search.jsp?q=" + quote(payload)
            res = self.request("GET", url)

            if res is None:
                continue

            body = res.text
            tested.append({
                "payload": payload,
                "status_code": res.status_code
            })

            if payload in body:
                reflected.append(payload)

        if reflected:
            status = "취약"
            risk = "High"
            evidence = f"입력한 XSS 페이로드가 응답에 필터링 없이 반사됨: {reflected[0]}"
        else:
            status = "양호"
            risk = "Low"
            evidence = "테스트한 XSS 페이로드가 응답에 그대로 반사되지 않음"

        return self.result(
            "WEB-004",
            "XSS",
            "웹애플리케이션 취약점",
            status,
            evidence,
            risk,
            "사용자 입력값 출력 시 HTML Escape를 적용하고 CSP를 설정한다.",
            self.target + "/vulnapp/search.jsp",
            {
                "tested": tested,
                "reflected": reflected
            }
        )

    # WEB-005 민감정보 노출
    def check_sensitive_info_exposure(self):
        url = self.target + "/vulnapp/debug.jsp"
        res = self.request("GET", url)

        if res is None:
            return self.result(
                "WEB-005",
                "민감정보 노출",
                "웹애플리케이션 취약점",
                "N/A",
                "debug.jsp에 접근할 수 없어 민감정보 노출 여부를 확인하지 못함",
                "N/A",
                "진단 대상 페이지 존재 여부를 확인한다.",
                url
            )

        body = res.text

        keyword_patterns = [
            r"password",
            r"passwd",
            r"api[_-]?key",
            r"secret",
            r"token",
            r"db_user",
            r"db_password",
            r"internal_ip"
        ]

        ip_patterns = [
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",
            r"192\.168\.\d{1,3}\.\d{1,3}"
        ]

        found = []

        for pattern in keyword_patterns + ip_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                found.append(pattern)

        if found:
            status = "취약"
            risk = "High"
            evidence = f"응답 본문에서 민감정보로 추정되는 키워드/패턴 탐지: {', '.join(found)}"
        else:
            status = "양호"
            risk = "Low"
            evidence = "응답 본문에서 주요 민감정보 키워드 또는 내부 IP 패턴이 탐지되지 않음"

        return self.result(
            "WEB-005",
            "민감정보 노출",
            "웹애플리케이션 취약점",
            status,
            evidence,
            risk,
            "디버그 페이지를 비활성화하고 API Key, DB 비밀번호, 내부 IP 등 민감정보를 응답에 포함하지 않는다.",
            url,
            {
                "matched_patterns": found,
                "sample_body": body[:500]
            }
        )

    # WEB-006 관리자 페이지 노출
    def check_admin_page_exposure(self):
        url = self.target + "/vulnapp/admin.jsp"
        res = self.request("GET", url)

        if res is None:
            return self.result(
                "WEB-006",
                "관리자 페이지 노출",
                "접근통제",
                "N/A",
                "admin.jsp에 접근할 수 없어 관리자 페이지 노출 여부를 확인하지 못함",
                "N/A",
                "관리자 페이지 URL과 서버 접속 상태를 확인한다.",
                url
            )

        admin_keywords = [
            "Admin Page",
            "System Config",
            "User List",
            "Backup Download",
            "관리자"
        ]

        body = res.text

        if res.status_code == 200 and any(k.lower() in body.lower() for k in admin_keywords):
            status = "취약"
            risk = "High"
            evidence = "인증 없이 관리자 페이지 접근 가능 및 관리자 관련 문구 확인"
        elif res.status_code in [401, 403]:
            status = "양호"
            risk = "Low"
            evidence = f"관리자 페이지 접근 시 {res.status_code} 응답으로 접근이 제한됨"
        elif res.status_code == 404:
            status = "N/A"
            risk = "N/A"
            evidence = "관리자 페이지가 존재하지 않음"
        else:
            status = "미흡"
            risk = "Medium"
            evidence = f"관리자 페이지 요청 결과 상태코드 {res.status_code}. 추가 수동 확인 필요"

        return self.result(
            "WEB-006",
            "관리자 페이지 노출",
            "접근통제",
            status,
            evidence,
            risk,
            "관리자 페이지는 인증과 권한 검증을 적용하고, 외부 직접 접근을 제한한다.",
            url,
            {
                "status_code": res.status_code,
                "headers": dict(res.headers)
            }
        )

    # WEB-007 Tomcat 기본 페이지 노출
    def check_tomcat_default_page(self):
        urls = [
            f"{self.scheme}://{self.host}:{self.tomcat_port}/",
            self.target + "/"
        ]

        keywords = [
            "Apache Tomcat",
            "If you're seeing this",
            "Manager App",
            "Host Manager"
        ]

        checked = []

        for url in urls:
            res = self.request("GET", url)
            if res is None:
                checked.append({"url": url, "reachable": False})
                continue

            body = res.text
            matched = [k for k in keywords if k.lower() in body.lower()]

            checked.append({
                "url": url,
                "reachable": True,
                "status_code": res.status_code,
                "matched": matched
            })

            if matched:
                return self.result(
                    "WEB-007",
                    "Tomcat 기본 페이지 노출",
                    "웹서버 설정",
                    "취약",
                    f"Tomcat 기본 페이지 관련 문구 탐지: {', '.join(matched)}",
                    "Low",
                    "운영 환경에서는 Tomcat 기본 ROOT 페이지와 예제 애플리케이션을 제거한다.",
                    url,
                    checked
                )

        return self.result(
            "WEB-007",
            "Tomcat 기본 페이지 노출",
            "웹서버 설정",
            "양호",
            "Tomcat 기본 페이지 관련 문구가 탐지되지 않음",
            "Low",
            "운영 환경에서는 기본 페이지가 배포되지 않도록 유지한다.",
            urls[0],
            checked
        )

    # WEB-008 Tomcat Manager 페이지 노출
    def check_tomcat_manager_exposure(self):
        urls = [
            f"{self.scheme}://{self.host}:{self.tomcat_port}/manager/html",
            self.target + "/manager/html"
        ]

        checked = []

        for url in urls:
            res = self.request("GET", url, allow_redirects=False)
            if res is None:
                checked.append({"url": url, "reachable": False})
                continue

            body = res.text[:1000]
            checked.append({
                "url": url,
                "status_code": res.status_code,
                "headers": dict(res.headers)
            })

            if res.status_code == 200 and ("Tomcat Web Application Manager" in body or "Manager App" in body):
                return self.result(
                    "WEB-008",
                    "Tomcat Manager 페이지 노출",
                    "웹서버 설정",
                    "취약",
                    "Tomcat Manager 페이지가 인증 없이 접근 가능하거나 관리 페이지 본문이 노출됨",
                    "High",
                    "Tomcat Manager 앱을 제거하거나 관리자 IP 제한, 강력한 인증, 접근제어를 적용한다.",
                    url,
                    checked
                )

            if res.status_code == 401:
                return self.result(
                    "WEB-008",
                    "Tomcat Manager 페이지 노출",
                    "웹서버 설정",
                    "미흡",
                    "Tomcat Manager 페이지가 외부에서 확인되며 인증 요청이 발생함. 접근 제한 필요",
                    "Medium",
                    "Manager 경로를 외부에서 접근하지 못하도록 제한하고, 필요 시 내부망 또는 관리자 IP에서만 접근하도록 설정한다.",
                    url,
                    checked
                )

            if res.status_code == 403:
                return self.result(
                    "WEB-008",
                    "Tomcat Manager 페이지 노출",
                    "웹서버 설정",
                    "양호",
                    "Tomcat Manager 페이지 접근이 403으로 제한됨",
                    "Low",
                    "현재 접근 제한 상태를 유지한다.",
                    url,
                    checked
                )

            if res.status_code == 404:
                continue

        return self.result(
            "WEB-008",
            "Tomcat Manager 페이지 노출",
            "웹서버 설정",
            "양호",
            "Tomcat Manager 페이지가 노출되지 않거나 404로 확인됨",
            "Low",
            "운영 환경에서는 Manager 애플리케이션을 제거하거나 접근 제한을 유지한다.",
            urls[0],
            checked
        )

    # WEB-009 HTTPS 미적용
    def check_https_not_applied(self):
        https_url = "https://" + self.host
        if self.parsed.port:
            https_url += f":{self.parsed.port}"

        http_url = "http://" + self.host
        if self.parsed.port:
            http_url += f":{self.parsed.port}"

        # HTTP 요청 시 HTTPS로 리다이렉트 되는지 확인
        http_res = self.request("GET", http_url, allow_redirects=False)

        redirect_to_https = False
        if http_res is not None:
            location = http_res.headers.get("Location", "")
            if http_res.status_code in [301, 302, 307, 308] and location.startswith("https://"):
                redirect_to_https = True

        # HTTPS 접속 가능 여부 확인
        https_available = False
        try:
            https_res = requests.get(
                https_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            https_available = https_res is not None
        except requests.RequestException:
            https_available = False

        if redirect_to_https and https_available:
            status = "양호"
            risk = "Low"
            evidence = "HTTP 요청이 HTTPS로 리다이렉트되고 HTTPS 접속이 가능함"
        elif https_available and not redirect_to_https:
            status = "미흡"
            risk = "Medium"
            evidence = "HTTPS 접속은 가능하지만 HTTP에서 HTTPS로 강제 리다이렉트되지 않음"
        else:
            status = "취약"
            risk = "Medium"
            evidence = "HTTPS 접속이 불가능하거나 HTTP 기반 서비스만 확인됨"

        return self.result(
            "WEB-009",
            "HTTPS 미적용",
            "웹서버 설정",
            status,
            evidence,
            risk,
            "TLS 인증서를 적용하고 HTTP 요청을 HTTPS로 리다이렉트하도록 설정한다.",
            http_url,
            {
                "https_url": https_url,
                "https_available": https_available,
                "redirect_to_https": redirect_to_https,
                "http_status": http_res.status_code if http_res else None
            }
        )

    # WEB-010 쿠키 보안 속성 미설정
    def check_cookie_security_flags(self):
        urls = [
            self.target + "/vulnapp/",
            self.target + "/vulnapp/login.jsp"
        ]

        cookies_found = []
        insecure_cookies = []

        for url in urls:
            res = self.request("GET", url)
            if res is None:
                continue

            set_cookie_headers = []

            # requests는 동일 헤더를 합칠 수 있으므로 raw headers 접근을 보조적으로 사용
            if "Set-Cookie" in res.headers:
                set_cookie_headers.append(res.headers.get("Set-Cookie"))

            for cookie_header in set_cookie_headers:
                cookies_found.append(cookie_header)

                lower_cookie = cookie_header.lower()
                missing_flags = []

                if "httponly" not in lower_cookie:
                    missing_flags.append("HttpOnly")
                if "secure" not in lower_cookie:
                    missing_flags.append("Secure")
                if "samesite" not in lower_cookie:
                    missing_flags.append("SameSite")

                if missing_flags:
                    insecure_cookies.append({
                        "cookie": cookie_header,
                        "missing_flags": missing_flags
                    })

        if not cookies_found:
            return self.result(
                "WEB-010",
                "쿠키 보안 속성 미설정",
                "웹서버 설정",
                "N/A",
                "Set-Cookie 헤더가 확인되지 않아 쿠키 보안 속성 진단 대상이 아님",
                "N/A",
                "세션 쿠키를 사용하는 경우 HttpOnly, Secure, SameSite 속성을 설정한다.",
                self.target + "/vulnapp/",
                {
                    "cookies_found": cookies_found
                }
            )

        if insecure_cookies:
            status = "취약"
            risk = "Medium"
            evidence = f"보안 속성이 누락된 쿠키 발견: {insecure_cookies}"
        else:
            status = "양호"
            risk = "Low"
            evidence = "확인된 쿠키에 HttpOnly, Secure, SameSite 속성이 설정되어 있음"

        return self.result(
            "WEB-010",
            "쿠키 보안 속성 미설정",
            "웹서버 설정",
            status,
            evidence,
            risk,
            "세션 쿠키에 HttpOnly, Secure, SameSite 속성을 설정한다. HTTPS 환경에서는 Secure 속성을 반드시 적용한다.",
            self.target + "/vulnapp/",
            {
                "cookies_found": cookies_found,
                "insecure_cookies": insecure_cookies
            }
        )

    def run_all(self):
        checks = [
            self.check_security_headers,
            self.check_server_info_exposure,
            self.check_sql_injection,
            self.check_xss,
            self.check_sensitive_info_exposure,
            self.check_admin_page_exposure,
            self.check_tomcat_default_page,
            self.check_tomcat_manager_exposure,
            self.check_https_not_applied,
            self.check_cookie_security_flags
        ]

        results = []

        for check in checks:
            try:
                print(f"[+] Running {check.__name__}")
                results.append(check())
                time.sleep(0.2)
            except Exception as e:
                results.append(self.result(
                    "ERROR",
                    check.__name__,
                    "시스템 오류",
                    "N/A",
                    f"진단 중 오류 발생: {str(e)}",
                    "N/A",
                    "진단 모듈의 예외 처리와 대상 URL을 확인한다."
                ))

        return results


def save_results(results, output_file):
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


def print_summary(results):
    total = len(results)
    vulnerable = sum(1 for r in results if r["auto_result"] == "취약")
    weak = sum(1 for r in results if r["auto_result"] == "미흡")
    good = sum(1 for r in results if r["auto_result"] == "양호")
    na = sum(1 for r in results if r["auto_result"] == "N/A")

    print("\n========== 자동 진단 요약 ==========")
    print(f"전체 진단 항목: {total}")
    print(f"취약: {vulnerable}")
    print(f"미흡: {weak}")
    print(f"양호: {good}")
    print(f"N/A: {na}")
    print("====================================\n")

    for r in results:
        print(f"[{r['check_id']}] {r['item']} -> {r['auto_result']} / Risk: {r['risk']}")
        print(f"  근거: {r['evidence']}")
        print()


def main():
    parser = argparse.ArgumentParser(description="4악다 웹 취약점 자동 진단 도구")
    parser.add_argument("--target", required=True, help="진단 대상 URL. 예: http://EC2_PUBLIC_IP")
    parser.add_argument("--tomcat-port", type=int, default=8080, help="Tomcat 직접 접근 포트. 기본값: 8080")
    parser.add_argument("--timeout", type=int, default=5, help="요청 타임아웃. 기본값: 5초")
    parser.add_argument("--output", default="auto_results.json", help="결과 저장 파일명")

    args = parser.parse_args()

    scanner = WebVulnScanner(
        target=args.target,
        tomcat_port=args.tomcat_port,
        timeout=args.timeout
    )

    results = scanner.run_all()
    save_results(results, args.output)
    print_summary(results)

    print(f"[+] 자동 진단 결과 저장 완료: {args.output}")


if __name__ == "__main__":
    main()