import argparse
import json
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()


class ExternalEvidenceCollector:
    """
    외부 진단 PC에서 대상 웹서비스에 HTTP 요청을 보내
    GPT 분석에 필요한 응답 헤더, 상태코드, 본문 샘플, 테스트 요청 결과를 수집한다.
    """

    def __init__(self, target: str, tomcat_port: int = 8080, timeout: int = 5):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.tomcat_port = tomcat_port

        parsed = urlparse(self.target)
        self.scheme = parsed.scheme or "http"
        self.host = parsed.hostname

        if not self.host:
            raise ValueError("target 형식이 올바르지 않습니다. 예: http://52.78.245.217")

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "4AKDA-GPT-Based-Scanner/1.0"
        })

    def safe_request(self, method: str, url: str, **kwargs):
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
        return self.response_to_dict(res)

    def collect_tomcat_default_page(self):
        urls = [
            f"{self.scheme}://{self.host}:{self.tomcat_port}/",
            self.target + "/"
        ]

        results = []
        for url in urls:
            res = self.safe_request("GET", url)
            results.append(self.response_to_dict(res))

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
            result = self.response_to_dict(res, body_limit=1000)

            result["test_payload"] = {
                "id": user_id,
                "pw": pw
            }

            if "body_sample" in result:
                body = result["body_sample"].lower()
                result["signature_hints"] = {
                    "contains_login_success": "login success" in body,
                    "contains_welcome": "welcome" in body,
                    "contains_role_admin": "role=admin" in body
                }

            results.append(result)

        return results

    def collect_xss_test(self):
        payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]

        results = []

        for payload in payloads:
            url = self.target + "/vulnapp/search.jsp?q=" + quote(payload)
            res = self.safe_request("GET", url)

            result = self.response_to_dict(res, body_limit=1000)
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
        result = self.response_to_dict(res, body_limit=1200)

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
                )
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

    def collect_all(self):
        return {
            "project": "4악다 생성형 AI 기반 웹 취약점 자동 진단",
            "target": self.target,
            "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "diagnosis_items": [
                {"check_id": "WEB-001", "item": "보안 헤더 미설정"},
                {"check_id": "WEB-002", "item": "서버 정보 노출"},
                {"check_id": "WEB-003", "item": "SQL Injection"},
                {"check_id": "WEB-004", "item": "XSS"},
                {"check_id": "WEB-005", "item": "민감정보 노출"},
                {"check_id": "WEB-006", "item": "관리자 페이지 노출"},
                {"check_id": "WEB-007", "item": "Tomcat 기본 페이지 노출"},
                {"check_id": "WEB-008", "item": "Tomcat Manager 페이지 노출"},
                {"check_id": "WEB-009", "item": "HTTPS 미적용"},
                {"check_id": "WEB-010", "item": "쿠키 보안 속성 미설정"}
            ],
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
                "cookie_status": self.collect_cookie_status()
            }
        }


class GPTVulnerabilityAnalyzer:
    """
    수집된 전체 evidence를 GPT에 전달해
    10개 취약점 항목에 대한 취약/양호/미흡/N/A 판단을 받는다.
    """

    def __init__(self, model: str):
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError(
                "OPENAI_API_KEY가 설정되어 있지 않습니다. "
                ".env 파일에 OPENAI_API_KEY를 입력하세요."
            )

        self.client = OpenAI()
        self.model = model

    def analyze(self, evidence: dict):
        prompt = f"""
너는 웹 취약점 진단 전문가다.

아래는 외부 진단 PC에서 Python으로 수집한 웹서비스 응답 데이터다.
이 데이터만 근거로 10개 진단 항목을 분석하라.

중요 규칙:
1. 실제 수집 데이터에 없는 사실은 절대 지어내지 마라.
2. 취약 여부는 취약, 양호, 미흡, N/A 중 하나로 판단하라.
3. 응답 데이터만으로 판단할 수 없으면 N/A로 판단하고 이유를 써라.
4. risk는 High, Medium, Low, N/A 중 하나로 판단하라.
5. evidence에는 어떤 응답, 상태코드, 헤더, 본문 샘플, 페이로드가 근거인지 구체적으로 써라.
6. recommendation은 실무 대응 방안을 1~2문장으로 작성하라.
7. 출력은 반드시 JSON 형식이어야 한다.

분석 대상:
WEB-001 보안 헤더 미설정
WEB-002 서버 정보 노출
WEB-003 SQL Injection
WEB-004 XSS
WEB-005 민감정보 노출
WEB-006 관리자 페이지 노출
WEB-007 Tomcat 기본 페이지 노출
WEB-008 Tomcat Manager 페이지 노출
WEB-009 HTTPS 미적용
WEB-010 쿠키 보안 속성 미설정

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
                    "name": "gpt_based_vulnerability_report",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "summary": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "target": {"type": "string"},
                                    "total_checks": {"type": "integer"},
                                    "vulnerable_count": {"type": "integer"},
                                    "weak_count": {"type": "integer"},
                                    "good_count": {"type": "integer"},
                                    "na_count": {"type": "integer"},
                                    "overall_comment": {"type": "string"}
                                },
                                "required": [
                                    "target",
                                    "total_checks",
                                    "vulnerable_count",
                                    "weak_count",
                                    "good_count",
                                    "na_count",
                                    "overall_comment"
                                ]
                            },
                            "findings": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "check_id": {"type": "string"},
                                        "item": {"type": "string"},
                                        "category": {"type": "string"},
                                        "gpt_result": {
                                            "type": "string",
                                            "enum": ["취약", "양호", "미흡", "N/A"]
                                        },
                                        "risk": {
                                            "type": "string",
                                            "enum": ["High", "Medium", "Low", "N/A"]
                                        },
                                        "evidence": {"type": "string"},
                                        "impact": {"type": "string"},
                                        "recommendation": {"type": "string"},
                                        "confidence": {
                                            "type": "string",
                                            "enum": ["High", "Medium", "Low"]
                                        }
                                    },
                                    "required": [
                                        "check_id",
                                        "item",
                                        "category",
                                        "gpt_result",
                                        "risk",
                                        "evidence",
                                        "impact",
                                        "recommendation",
                                        "confidence"
                                    ]
                                }
                            }
                        },
                        "required": ["summary", "findings"]
                    }
                }
            }
        )

        return json.loads(response.output_text)


def save_json(path: str, data: dict):
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def print_report(report: dict):
    summary = report["summary"]

    print("\n========== GPT 기반 자동 진단 요약 ==========")
    print(f"대상: {summary['target']}")
    print(f"전체 진단 항목: {summary['total_checks']}")
    print(f"취약: {summary['vulnerable_count']}")
    print(f"미흡: {summary['weak_count']}")
    print(f"양호: {summary['good_count']}")
    print(f"N/A: {summary['na_count']}")
    print(f"총평: {summary['overall_comment']}")
    print("============================================\n")

    for finding in report["findings"]:
        print(
            f"[{finding['check_id']}] {finding['item']} "
            f"-> {finding['gpt_result']} / Risk: {finding['risk']}"
        )
        print(f"  근거: {finding['evidence']}")
        print(f"  영향: {finding['impact']}")
        print(f"  대응: {finding['recommendation']}")
        print(f"  신뢰도: {finding['confidence']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="외부 진단용 GPT 기반 웹 취약점 자동 진단 서비스"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="진단 대상 URL. 예: http://52.78.245.217"
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
        "--output",
        default="outputs/gpt_analysis_results.json",
        help="GPT 분석 결과 저장 파일"
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

    print("[2] GPT 기반 취약점 분석 중...")

    analyzer = GPTVulnerabilityAnalyzer(model=args.model)
    report = analyzer.analyze(evidence)

    save_json(args.output, report)
    print_report(report)

    print(f"[+] GPT 분석 결과 저장 완료: {args.output}")


if __name__ == "__main__":
    main()