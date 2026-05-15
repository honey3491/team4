import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()

HEADERS = {"User-Agent": "4AKDA-GPT-Based-Scanner/3.3"}


def make_scan_id():
    return "SCAN-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save_json(path: str, data: dict):
    """
    기존 파일이 있어도 새 파일명을 만들지 않고 그대로 덮어쓴다.
    """
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def find_signature_result_path():
    """
    rule.py 실행 후 생성된 result.json을 자동으로 찾는다.

    기본 탐색 순서:
    1. 환경변수 SIGNATURE_RESULT_PATH
    2. 현재 gpt-vuln-scanner 폴더의 result.json
    3. 현재 gpt-vuln-scanner 폴더의 scan_result.json
    4. 상위 폴더의 rule-vuln-scanner/result.json
    5. 상위 폴더의 rule-vuln-scanner/scan_result.json
    6. 현재 작업 디렉터리의 result.json
    7. 현재 작업 디렉터리의 scan_result.json
    """
    current_dir = Path(__file__).resolve().parent
    project_root = current_dir.parent

    candidates = []

    env_path = os.getenv("SIGNATURE_RESULT_PATH")
    if env_path:
        candidates.append(Path(env_path))

    candidates.extend([
        current_dir / "result.json",
        current_dir / "scan_result.json",
        project_root / "rule-vuln-scanner" / "result.json",
        project_root / "rule-vuln-scanner" / "scan_result.json",
        Path.cwd() / "result.json",
        Path.cwd() / "scan_result.json",
    ])

    for path in candidates:
        if path.exists() and path.is_file():
            return path

    return None


def load_signature_result_auto():
    """
    rule.py가 생성한 signature-based result.json을 자동으로 읽는다.
    찾지 못하면 None을 반환하고 GPT evidence 기반으로만 분석한다.
    """
    signature_path = find_signature_result_path()

    if not signature_path:
        return None, None

    with open(signature_path, "r", encoding="utf-8") as f:
        return json.load(f), str(signature_path)


def summarize_signature_evidence(evidence):
    """
    rule.py 결과의 evidence를 GPT에 전달하기 좋은 요약 형태로 변환한다.
    SQL Injection의 sqlmap raw_tail처럼 너무 긴 값은 제외한다.
    """
    if isinstance(evidence, str):
        return evidence

    if not isinstance(evidence, dict):
        return str(evidence)

    summarized = {}

    for key, value in evidence.items():
        if key == "sqlmap" and isinstance(value, dict):
            summarized["sqlmap"] = {
                "returncode": value.get("returncode"),
                "dbms_banner": value.get("dbms_banner"),
                "current_user": value.get("current_user"),
                "current_db": value.get("current_db"),
                "is_dba": value.get("is_dba"),
                "databases": value.get("databases"),
                "error": value.get("error")
            }
        elif key in ["raw_tail", "command"]:
            continue
        else:
            summarized[key] = value

    return summarized


def force_owasp_2025(owasp_value: str):
    """
    최소 보정용 함수.
    GPT가 혹시 2021을 출력하면 2025로 교체한다.
    """
    value = str(owasp_value).strip()
    value = value.replace(":2021", ":2025")
    value = value.replace("2021-", "2025 ")
    return value


def simplify_signature_report(signature_report: dict | None):
    """
    GPT 최종 판단에 참고할 최소한의 signature-based 결과 요약.
    result.json 전체를 그대로 복사하지 않도록 evidence를 요약한다.
    """
    if not signature_report:
        return None

    simplified_results = []

    for item in signature_report.get("results", []):
        simplified_results.append({
            "check_id": item.get("check_id"),
            "owasp": force_owasp_2025(item.get("owasp", "")),
            "name": item.get("name"),
            "severity": item.get("severity"),
            "evidence_summary": summarize_signature_evidence(item.get("evidence")),
            "recommendation_summary": item.get("recommendation")
        })

    return {
        "scan_id": signature_report.get("scan_id"),
        "target": signature_report.get("target"),
        "scanner": signature_report.get("scanner"),
        "generated_at": signature_report.get("generated_at"),
        "summary": signature_report.get("summary"),
        "results": simplified_results
    }


class ExternalEvidenceCollector:
    """
    외부 진단 PC에서 대상 웹서비스에 HTTP 요청을 보내
    GPT 분석에 필요한 응답 헤더, 상태코드, 본문 샘플, 테스트 요청 결과를 수집한다.

    이 클래스는 최종 취약 여부를 확정하지 않고,
    GPT가 1차 판단할 수 있도록 관찰 가능한 evidence를 모은다.
    """

    def __init__(self, target: str, tomcat_port: int = 8080, timeout: int = 5):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.tomcat_port = tomcat_port

        parsed = urlparse(self.target)
        self.scheme = parsed.scheme or "http"
        self.host = parsed.hostname

        if not self.host:
            raise ValueError("target 형식이 올바르지 않습니다. 예: http://15.164.60.79")

        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def safe_request(self, method: str, url: str, **kwargs):
        try:
            return self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                allow_redirects=kwargs.pop("allow_redirects", False),
                verify=False,
                **kwargs
            )
        except requests.RequestException as e:
            return {
                "error": str(e),
                "url": url
            }

    def response_to_dict(self, response, include_body=True, body_limit=1500):
        if isinstance(response, dict) and "error" in response:
            return response

        data = {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
        }

        if include_body:
            data["body_sample"] = response.text[:body_limit]

        return data

    def collect_basic_page(self):
        url = self.target + "/"
        res = self.safe_request("GET", url)
        return self.response_to_dict(res)

    def collect_error_page(self):
        url = self.target + "/not_exist_4akda_404_test"
        res = self.safe_request("GET", url)
        return self.response_to_dict(res, body_limit=2000)

    def collect_tomcat_default_page(self):
        urls = [
            f"{self.scheme}://{self.host}:{self.tomcat_port}/",
            self.target + "/"
        ]

        results = []

        for url in urls:
            res = self.safe_request("GET", url)
            results.append(self.response_to_dict(res, body_limit=1500))

        return results

    def collect_tomcat_manager(self):
        urls = [
            f"{self.scheme}://{self.host}:{self.tomcat_port}/manager/html",
            self.target + "/manager/html"
        ]

        results = []

        for url in urls:
            res = self.safe_request("GET", url, allow_redirects=False)
            results.append(self.response_to_dict(res, body_limit=800))

        return results

    def collect_sqli_test(self):
        payloads = [
            ("admin'--", "test"),
            ("' OR '1'='1' -- ", "test"),
            ("admin", "' OR '1'='1' -- ")
        ]

        results = []

        for user_id, pw in payloads:
            url = (
                self.target
                + "/vulnapp/login.jsp?id="
                + quote(user_id)
                + "&pw="
                + quote(pw)
            )

            res = self.safe_request("GET", url)
            result = self.response_to_dict(res, body_limit=1200)

            result["test_type"] = "SQL Injection authentication bypass test"
            result["test_payload"] = {
                "id": user_id,
                "pw": pw
            }

            if "body_sample" in result:
                body = result["body_sample"].lower()
                result["signature_hints"] = {
                    "contains_login_success": "login success" in body,
                    "contains_welcome": "welcome" in body,
                    "contains_logout": "logout" in body,
                    "contains_admin": "admin" in body,
                    "contains_dashboard": "dashboard" in body,
                    "contains_role_admin": "role=admin" in body
                }

            results.append(result)

        return results

    def collect_xss_test(self):
        payloads = [
            "<script>alert(1337)</script>",
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]

        results = []

        for payload in payloads:
            url = self.target + "/vulnapp/search.jsp?q=" + quote(payload)
            res = self.safe_request("GET", url)

            result = self.response_to_dict(res, body_limit=1200)
            result["test_type"] = "Reflected XSS test"
            result["test_payload"] = payload

            if "body_sample" in result:
                result["signature_hints"] = {
                    "payload_reflected": payload in result["body_sample"]
                }

            results.append(result)

        return results

    def collect_sensitive_info_page(self):
        url = self.target + "/vulnapp/debug.jsp"
        res = self.safe_request("GET", url)
        result = self.response_to_dict(res, body_limit=1500)

        if "body_sample" in result:
            body = result["body_sample"]
            patterns = [
                r"password",
                r"passwd",
                r"api[_-]?key",
                r"secret",
                r"token",
                r"db_user",
                r"db_password",
                r"internal_ip",
                r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",
                r"192\.168\.\d{1,3}\.\d{1,3}"
            ]

            matched = [
                pattern
                for pattern in patterns
                if re.search(pattern, body, re.IGNORECASE)
            ]

            result["signature_hints"] = {
                "matched_sensitive_patterns": matched
            }

        return result

    def collect_admin_page(self):
        url = self.target + "/vulnapp/admin.jsp"
        res = self.safe_request("GET", url)
        result = self.response_to_dict(res, body_limit=1200)

        if "body_sample" in result:
            body = result["body_sample"].lower()
            result["signature_hints"] = {
                "contains_admin_keywords": any(
                    keyword in body
                    for keyword in [
                        "admin page",
                        "system config",
                        "user list",
                        "backup download",
                        "관리자"
                    ]
                ),
                "contains_login_keyword": "login" in body
            }

        return result

    def collect_https_status(self):
        http_url = "http://" + self.host
        https_url = "https://" + self.host

        http_res = self.safe_request("GET", http_url, allow_redirects=False)

        try:
            https_res = requests.get(
                https_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            https_data = self.response_to_dict(https_res, include_body=False)
            https_available = True
        except requests.RequestException as e:
            https_data = {
                "url": https_url,
                "error": str(e)
            }
            https_available = False

        redirect_to_https = False

        if not isinstance(http_res, dict):
            location = http_res.headers.get("Location", "")
            if http_res.status_code in [301, 302, 307, 308] and location.startswith("https://"):
                redirect_to_https = True

        return {
            "http": self.response_to_dict(http_res, include_body=False),
            "https": https_data,
            "https_available": https_available,
            "redirect_to_https": redirect_to_https
        }

    def collect_cookie_status(self):
        urls = [
            self.target + "/",
            self.target + "/vulnapp/",
            self.target + "/vulnapp/login.jsp"
        ]

        results = []

        for url in urls:
            res = self.safe_request("GET", url)

            if isinstance(res, dict):
                results.append(res)
                continue

            set_cookie = res.headers.get("Set-Cookie", "")
            lower_cookie = set_cookie.lower()

            results.append({
                "url": url,
                "status_code": res.status_code,
                "set_cookie": set_cookie,
                "cookie_flags": {
                    "has_cookie": bool(set_cookie),
                    "httponly": "httponly" in lower_cookie,
                    "secure": "secure" in lower_cookie,
                    "samesite": "samesite" in lower_cookie
                }
            })

        return results

    def collect_rate_limit(self):
        url = self.target + "/vulnapp/login.jsp"

        attempts = []
        blocked = False

        for _ in range(8):
            res = self.safe_request(
                "POST",
                url,
                data={
                    "username": "admin",
                    "password": "wrongpass"
                }
            )

            if isinstance(res, dict):
                attempts.append(res)
                continue

            attempts.append({
                "url": res.url,
                "status_code": res.status_code,
                "body_sample": res.text[:300]
            })

            if res.status_code in [423, 429]:
                blocked = True

        return {
            "url": url,
            "attempt_count": len(attempts),
            "blocked": blocked,
            "attempts": attempts
        }

    def collect_account_lockout(self):
        url = self.target + "/vulnapp/login.jsp"

        attempts = []
        blocked = False

        for _ in range(10):
            res = self.safe_request(
                "POST",
                url,
                data={
                    "username": "admin",
                    "password": "wrongpass"
                }
            )

            if isinstance(res, dict):
                attempts.append(res)
                continue

            attempts.append({
                "url": res.url,
                "status_code": res.status_code,
                "body_sample": res.text[:300]
            })

            if res.status_code in [423, 429]:
                blocked = True

        return {
            "url": url,
            "attempt_count": len(attempts),
            "blocked": blocked,
            "attempts": attempts
        }

    def collect_debug_true(self):
        url = self.target + "/vulnapp/"
        res = self.safe_request("GET", url, params={"debug": "true"})
        result = self.response_to_dict(res, body_limit=1200)

        if "body_sample" in result:
            body = result["body_sample"].lower()
            result["signature_hints"] = {
                "contains_debug_keywords": any(
                    keyword in body
                    for keyword in [
                        "debug",
                        "env",
                        "classpath",
                        "config",
                        "stacktrace"
                    ]
                )
            }

        return result

    def collect_optional_endpoint_status(self):
        """
        GPT가 존재하지 않는 기능을 임의로 만들지 않게 하기 위해
        대표적인 추가 취약점 엔드포인트의 존재 여부만 수집한다.
        """
        endpoints = [
            "/vulnapp/upload.jsp",
            "/vulnapp/board.jsp",
            "/fetch",
            "/vulnapp/user.jsp?id=1",
            "/vulnapp/ping.jsp",
            "/vulnapp/register.jsp",
            "/vulnapp/api/profile"
        ]

        results = []

        for endpoint in endpoints:
            url = self.target + endpoint
            res = self.safe_request("GET", url)

            if isinstance(res, dict):
                results.append({
                    "endpoint": endpoint,
                    "url": url,
                    "reachable": False,
                    "error": res.get("error")
                })
                continue

            results.append({
                "endpoint": endpoint,
                "url": url,
                "reachable": True,
                "status_code": res.status_code,
                "body_sample": res.text[:300]
            })

        return results

    def collect_all(self):
        return {
            "project": "4악다 생성형 AI 기반 웹 취약점 자동 진단",
            "target": self.target,
            "collected_at": now_utc(),
            "analysis_policy": {
                "phase_1": "GPT first analyzes collected HTTP evidence only.",
                "phase_2": "If GPT marks a finding as 보류 or low confidence, signature-based result.json may be used as supporting evidence.",
                "final_output": "Signature-compatible JSON structure using WEB-Axx-xxx and OWASP 2025 labels."
            },
            "collected_evidence": {
                "basic_page": self.collect_basic_page(),
                "error_page": self.collect_error_page(),
                "tomcat_default_page": self.collect_tomcat_default_page(),
                "tomcat_manager": self.collect_tomcat_manager(),
                "sqli_tests": self.collect_sqli_test(),
                "xss_tests": self.collect_xss_test(),
                "sensitive_info_page": self.collect_sensitive_info_page(),
                "admin_page": self.collect_admin_page(),
                "https_status": self.collect_https_status(),
                "cookie_status": self.collect_cookie_status(),
                "rate_limit": self.collect_rate_limit(),
                "account_lockout": self.collect_account_lockout(),
                "debug_true": self.collect_debug_true(),
                "optional_endpoint_status": self.collect_optional_endpoint_status()
            }
        }


class GPTVulnerabilityAnalyzer:
    def __init__(self, model: str):
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError(
                "OPENAI_API_KEY가 설정되어 있지 않습니다. "
                ".env 파일에 OPENAI_API_KEY를 입력하세요."
            )

        self.client = OpenAI()
        self.model = model

    def initial_analyze(self, evidence: dict):
        prompt = f"""
너는 웹 취약점 진단 전문가다.

아래는 외부 진단 PC에서 Python으로 수집한 웹서비스 응답 데이터다.
이 데이터만 근거로 1차 취약점 판단을 수행하라.

중요 규칙:
1. 이 단계에서는 signature-based 결과를 사용하지 않는다.
2. 실제 수집 데이터에 없는 사실은 절대 지어내지 마라.
3. 수집 데이터만으로 명확히 판단 가능한 항목은 취약, 양호, 미흡 중 하나로 판단하라.
4. 수집 데이터가 부족하거나 확실하지 않은 항목은 보류로 판단하라.
5. OWASP는 반드시 2025 기준으로 작성하라. "2021"이라는 문자열은 절대 출력하지 마라.
6. OWASP 형식은 반드시 "A01:2025 Broken Access Control"처럼 연도 뒤에 공백을 사용하라.
7. check_id는 반드시 WEB-Axx-xxx 형식으로 작성하라. 예: WEB-A01-001
8. ADMIN_DIRECT_ACCESS, SQL_INJECTION, SECURITY_HEADERS 같은 임의 문자열 check_id는 사용하지 마라.
9. upload.jsp, board.jsp, fetch, user.jsp, ping.jsp, register.jsp, api/profile 등 존재가 확인되지 않은 엔드포인트 취약점은 생성하지 마라.
10. evidence에는 어떤 응답, 상태코드, 헤더, 본문 샘플, 테스트 반응이 근거인지 구체적으로 작성하라.
11. severity는 critical, high, medium, low, na 중 하나로 작성하라.
12. confidence는 High, Medium, Low 중 하나로 작성하라.
13. 출력은 반드시 JSON 형식이어야 한다.

권장 check_id 및 OWASP 2025 매핑:
- 관리자 페이지 직접 접근: WEB-A01-001 / A01:2025 Broken Access Control
- IDOR: WEB-A01-002 / A01:2025 Broken Access Control
- 보안 헤더 미설정: WEB-A02-001 / A02:2025 Security Misconfiguration
- 서버 버전 노출: WEB-A02-002 / A02:2025 Security Misconfiguration
- Tomcat Manager 노출: WEB-A02-003 / A02:2025 Security Misconfiguration
- 민감정보 노출: WEB-A02-004 / A02:2025 Security Misconfiguration
- HTTPS 미적용: WEB-A04-001 / A04:2025 Cryptographic Failures
- 쿠키 Secure/HttpOnly 미설정: WEB-A04-002 / A04:2025 Cryptographic Failures
- SQL Injection: WEB-A05-001 / A05:2025 Injection
- Reflected XSS: WEB-A05-002 / A05:2025 Injection
- Stored XSS: WEB-A05-003 / A05:2025 Injection
- Command Injection: WEB-A05-004 / A05:2025 Injection
- 로그인 Rate Limit 미구현: WEB-A06-001 / A06:2025 Insecure Design
- debug=true 기능 활성화: WEB-A06-002 / A06:2025 Insecure Design
- 계정 잠금 미구현: WEB-A07-001 / A07:2025 Authentication Failures
- 약한 비밀번호 허용: WEB-A07-002 / A07:2025 Authentication Failures
- JWT 검증 우회: WEB-A07-003 / A07:2025 Authentication Failures
- 웹쉘 업로드 가능: WEB-A08-001 / A08:2025 Software or Data Integrity Failures
- 로그인 실패 로그 미기록: WEB-A09-001 / A09:2025 Logging & Alerting Failures
- 관리자 행위 로그 미기록: WEB-A09-002 / A09:2025 Logging & Alerting Failures
- Stack Trace 노출: WEB-A10-001 / A10:2025 Mishandling of Exceptional Conditions
- SSRF: WEB-A10-002 / A10:2025 Mishandling of Exceptional Conditions

수집 데이터:
{json.dumps(evidence, ensure_ascii=False, indent=2)}
"""

        response = self.client.responses.create(
            model=self.model,
            reasoning={"effort": "low"},
            input=prompt,
            text={
                "format": {
                    "type": "json_schema",
                    "name": "gpt_initial_vulnerability_assessment",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "assessments": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "check_id": {
                                            "type": "string",
                                            "pattern": "^WEB-A[0-9]{2}-[0-9]{3}$"
                                        },
                                        "owasp": {
                                            "type": "string",
                                            "pattern": "^A[0-9]{2}:2025 .+"
                                        },
                                        "name": {"type": "string"},
                                        "result": {
                                            "type": "string",
                                            "enum": ["취약", "미흡", "양호", "N/A", "보류"]
                                        },
                                        "severity": {
                                            "type": "string",
                                            "enum": ["critical", "high", "medium", "low", "na"]
                                        },
                                        "evidence": {"type": "string"},
                                        "recommendation": {"type": "string"},
                                        "confidence": {
                                            "type": "string",
                                            "enum": ["High", "Medium", "Low"]
                                        },
                                        "defer_reason": {"type": "string"}
                                    },
                                    "required": [
                                        "check_id",
                                        "owasp",
                                        "name",
                                        "result",
                                        "severity",
                                        "evidence",
                                        "recommendation",
                                        "confidence",
                                        "defer_reason"
                                    ]
                                }
                            }
                        },
                        "required": ["assessments"]
                    }
                }
            }
        )

        return json.loads(response.output_text)

    def final_analyze(self, evidence: dict, initial_report: dict, signature_report: dict | None):
        scan_id = make_scan_id()
        generated_at = now_utc()
        target = evidence.get("target", "")
        simplified_signature = simplify_signature_report(signature_report)

        prompt = f"""
너는 웹 취약점 진단 전문가다.

아래 데이터는 세 종류로 구성되어 있다.

1. collected_evidence:
   외부 진단 PC에서 직접 수집한 HTTP 응답, 상태코드, 헤더, 본문 샘플, 테스트 요청 결과

2. gpt_initial_assessment:
   GPT가 collected_evidence만 보고 수행한 1차 판단 결과

3. signature_based_report:
   rule.py가 생성한 시그니처 기반 자동 진단 결과 요약
   이 데이터는 1차 판단이 보류되었거나 confidence가 낮은 항목에 대해서만 보조 근거로 사용한다.

최종 판단 규칙:
1. GPT 1차 판단이 취약 또는 미흡이고 confidence가 High 또는 Medium이면 이를 우선한다.
2. GPT 1차 판단이 보류, N/A, 또는 confidence Low인 항목은 signature_based_report를 참고해 최종 판단할 수 있다.
3. signature_based_report를 참고한 경우 evidence에 "시그니처 기반 보조 근거"라고 명시하라.
4. collected_evidence와 signature_based_report가 서로 모순되면 보수적으로 판단하고 evidence에 모순을 설명하라.
5. signature_based_report에만 있고 collected_evidence가 부족한 항목은 포함할 수 있지만, evidence에 "GPT 1차 판단 보류 후 시그니처 기반 결과 참고"라고 명시하라.
6. 둘 중 어디에도 근거가 없는 취약점은 생성하지 마라.
7. OWASP는 반드시 2025 기준으로 작성하라. "2021"이라는 문자열은 절대 출력하지 마라.
8. OWASP 형식은 반드시 "A01:2025 Broken Access Control"처럼 연도 뒤에 공백을 사용하라.
9. check_id는 반드시 WEB-Axx-xxx 형식으로 작성하라. 예: WEB-A01-001
10. ADMIN_DIRECT_ACCESS, SQL_INJECTION, SECURITY_HEADERS 같은 임의 문자열 check_id는 사용하지 마라.
11. upload.jsp, board.jsp, fetch, user.jsp, ping.jsp, register.jsp, api/profile 등 존재가 확인되지 않은 엔드포인트 취약점은 생성하지 마라.
12. severity는 critical, high, medium, low 중 하나로 작성하라.
13. results의 id는 RES-0001부터 순서대로 작성하라.
14. summary.total은 results 개수와 같아야 한다.
15. summary.severity는 results의 severity 개수를 집계한 값이어야 한다.
16. 출력은 반드시 JSON 형식이어야 한다.
17. 공격 절차를 자세히 설명하지 말고, 방어적 진단 결과와 조치 중심으로 작성하라.

메타데이터:
scan_id: {scan_id}
target: {target}
scanner: gpt-based
generated_at: {generated_at}

권장 check_id 및 OWASP 2025 매핑:
- 관리자 페이지 직접 접근: WEB-A01-001 / A01:2025 Broken Access Control
- IDOR: WEB-A01-002 / A01:2025 Broken Access Control
- 보안 헤더 미설정: WEB-A02-001 / A02:2025 Security Misconfiguration
- 서버 버전 노출: WEB-A02-002 / A02:2025 Security Misconfiguration
- Tomcat Manager 노출: WEB-A02-003 / A02:2025 Security Misconfiguration
- 민감정보 노출: WEB-A02-004 / A02:2025 Security Misconfiguration
- HTTPS 미적용: WEB-A04-001 / A04:2025 Cryptographic Failures
- 쿠키 Secure/HttpOnly 미설정: WEB-A04-002 / A04:2025 Cryptographic Failures
- SQL Injection: WEB-A05-001 / A05:2025 Injection
- Reflected XSS: WEB-A05-002 / A05:2025 Injection
- Stored XSS: WEB-A05-003 / A05:2025 Injection
- Command Injection: WEB-A05-004 / A05:2025 Injection
- 로그인 Rate Limit 미구현: WEB-A06-001 / A06:2025 Insecure Design
- debug=true 기능 활성화: WEB-A06-002 / A06:2025 Insecure Design
- 계정 잠금 미구현: WEB-A07-001 / A07:2025 Authentication Failures
- 약한 비밀번호 허용: WEB-A07-002 / A07:2025 Authentication Failures
- JWT 검증 우회: WEB-A07-003 / A07:2025 Authentication Failures
- 웹쉘 업로드 가능: WEB-A08-001 / A08:2025 Software or Data Integrity Failures
- 로그인 실패 로그 미기록: WEB-A09-001 / A09:2025 Logging & Alerting Failures
- 관리자 행위 로그 미기록: WEB-A09-002 / A09:2025 Logging & Alerting Failures
- Stack Trace 노출: WEB-A10-001 / A10:2025 Mishandling of Exceptional Conditions
- SSRF: WEB-A10-002 / A10:2025 Mishandling of Exceptional Conditions

collected_evidence:
{json.dumps(evidence, ensure_ascii=False, indent=2)}

gpt_initial_assessment:
{json.dumps(initial_report, ensure_ascii=False, indent=2)}

signature_based_report:
{json.dumps(simplified_signature, ensure_ascii=False, indent=2)}
"""

        response = self.client.responses.create(
            model=self.model,
            reasoning={"effort": "low"},
            input=prompt,
            text={
                "format": {
                    "type": "json_schema",
                    "name": "gpt_final_vulnerability_report",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "scan_id": {"type": "string"},
                            "target": {"type": "string"},
                            "scanner": {
                                "type": "string",
                                "enum": ["gpt-based"]
                            },
                            "generated_at": {"type": "string"},
                            "summary": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "total": {"type": "integer"},
                                    "severity": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "properties": {
                                            "critical": {"type": "integer"},
                                            "high": {"type": "integer"},
                                            "medium": {"type": "integer"},
                                            "low": {"type": "integer"}
                                        },
                                        "required": [
                                            "critical",
                                            "high",
                                            "medium",
                                            "low"
                                        ]
                                    }
                                },
                                "required": [
                                    "total",
                                    "severity"
                                ]
                            },
                            "results": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "id": {"type": "string"},
                                        "check_id": {
                                            "type": "string",
                                            "pattern": "^WEB-A[0-9]{2}-[0-9]{3}$"
                                        },
                                        "owasp": {
                                            "type": "string",
                                            "pattern": "^A[0-9]{2}:2025 .+"
                                        },
                                        "name": {"type": "string"},
                                        "severity": {
                                            "type": "string",
                                            "enum": [
                                                "critical",
                                                "high",
                                                "medium",
                                                "low"
                                            ]
                                        },
                                        "evidence": {"type": "string"},
                                        "recommendation": {"type": "string"}
                                    },
                                    "required": [
                                        "id",
                                        "check_id",
                                        "owasp",
                                        "name",
                                        "severity",
                                        "evidence",
                                        "recommendation"
                                    ]
                                }
                            }
                        },
                        "required": [
                            "scan_id",
                            "target",
                            "scanner",
                            "generated_at",
                            "summary",
                            "results"
                        ]
                    }
                }
            }
        )

        report = json.loads(response.output_text)

        report["scan_id"] = scan_id
        report["target"] = target
        report["scanner"] = "gpt-based"
        report["generated_at"] = generated_at

        report["results"] = self.normalize_results(report.get("results", []))
        report["summary"] = self.build_summary(report["results"])

        return report

    def normalize_results(self, results):
        normalized = []
        allowed_severities = {"critical", "high", "medium", "low"}

        for idx, item in enumerate(results, start=1):
            severity = str(item.get("severity", "low")).lower()

            if severity not in allowed_severities:
                severity = "low"

            check_id = str(item.get("check_id", "")).strip()
            owasp = force_owasp_2025(str(item.get("owasp", "")).strip())

            normalized.append({
                "id": f"RES-{idx:04d}",
                "check_id": check_id,
                "owasp": owasp,
                "name": str(item.get("name", "")).strip(),
                "severity": severity,
                "evidence": str(item.get("evidence", "")).strip(),
                "recommendation": str(item.get("recommendation", "")).strip()
            })

        return normalized

    def build_summary(self, results):
        severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for item in results:
            sev = item.get("severity")
            if sev in severity:
                severity[sev] += 1

        return {
            "total": len(results),
            "severity": severity
        }


def print_report(report: dict):
    summary = report["summary"]
    severity = summary["severity"]

    print("\n========== GPT 기반 자동 진단 요약 ==========")
    print(f"Scan ID: {report['scan_id']}")
    print(f"대상: {report['target']}")
    print(f"스캐너: {report['scanner']}")
    print(f"생성 시각: {report['generated_at']}")
    print(f"전체 탐지 결과: {summary['total']}")
    print(f"Critical: {severity['critical']}")
    print(f"High: {severity['high']}")
    print(f"Medium: {severity['medium']}")
    print(f"Low: {severity['low']}")
    print("============================================\n")

    for finding in report["results"]:
        print(
            f"[{finding['id']}] {finding['name']} "
            f"({finding['check_id']}) / Severity: {finding['severity']}"
        )
        print(f"  OWASP: {finding['owasp']}")
        print(f"  근거: {finding['evidence']}")
        print(f"  대응: {finding['recommendation']}")
        print()


def main():
    requests.packages.urllib3.disable_warnings()

    parser = argparse.ArgumentParser(
        description="외부 진단용 GPT 기반 웹 취약점 자동 진단 서비스"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="진단 대상 URL. 예: http://15.164.60.79"
    )

    parser.add_argument(
        "--tomcat-port",
        type=int,
        default=8080,
        help="Tomcat 직접 접근 포트. 기본값: 8080"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="요청 타임아웃. 기본값: 5초"
    )

    parser.add_argument(
        "--model",
        default=os.getenv("OPENAI_MODEL", "gpt-5.5"),
        help="OpenAI 모델명. 기본값: .env의 OPENAI_MODEL 또는 gpt-5.5"
    )

    parser.add_argument(
        "--evidence-output",
        default="outputs/gpt_evidence.json",
        help="수집 증거 저장 파일"
    )

    parser.add_argument(
        "--initial-output",
        default="outputs/gpt_initial_assessment.json",
        help="GPT 1차 판단 결과 저장 파일"
    )

    parser.add_argument(
        "--output",
        default="outputs/gpt_analysis_results.json",
        help="GPT 최종 분석 결과 저장 파일"
    )

    args = parser.parse_args()

    print("[1] 외부에서 웹서비스 응답 데이터 수집 중...")

    collector = ExternalEvidenceCollector(
        target=args.target,
        tomcat_port=args.tomcat_port,
        timeout=args.timeout
    )

    evidence = collector.collect_all()
    save_json(args.evidence_output, evidence)
    print(f"[+] 수집 증거 저장 완료: {args.evidence_output}")

    signature_report, signature_path = load_signature_result_auto()

    if signature_report:
        print(f"[+] signature-based 결과 자동 로드 완료: {signature_path}")
    else:
        print("[!] signature-based result.json을 찾지 못했습니다.")
        print("[!] GPT evidence 기반으로만 분석합니다.")
        print("[!] rule.py를 먼저 실행해 rule-vuln-scanner/result.json을 생성하면 보류 항목 판단에 활용됩니다.")

    analyzer = GPTVulnerabilityAnalyzer(model=args.model)

    print("[2] GPT 1차 판단 중...")
    initial_report = analyzer.initial_analyze(evidence)
    save_json(args.initial_output, initial_report)
    print(f"[+] GPT 1차 판단 결과 저장 완료: {args.initial_output}")

    print("[3] GPT 최종 판단 중...")
    report = analyzer.final_analyze(
        evidence=evidence,
        initial_report=initial_report,
        signature_report=signature_report
    )

    save_json(args.output, report)
    print_report(report)

    print(f"[+] GPT 최종 분석 결과 저장 완료: {args.output}")


if __name__ == "__main__":
    main()