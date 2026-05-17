import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from openai import OpenAI
from pydantic import BaseModel, Field


load_dotenv()

HEADERS = {"User-Agent": "4AKDA-GPT-Based-Scanner/3.3"}
KST = timezone(timedelta(hours=9))

CHECK_CATALOG = [
    {"check_id":"WEB-A01-001","owasp":"A01:2025 Broken Access Control","name":"관리자 페이지 직접 접근","url":"/vulnapp/admin.jsp"},
    {"check_id":"WEB-A01-002","owasp":"A01:2025 Broken Access Control","name":"IDOR","url":"/vulnapp/profile.jsp?user_idx=1"},
    {"check_id":"WEB-A02-001","owasp":"A02:2025 Security Misconfiguration","name":"보안 헤더 미설정","url":"/"},
    {"check_id":"WEB-A02-002","owasp":"A02:2025 Security Misconfiguration","name":"서버 버전 노출","url":"/"},
    {"check_id":"WEB-A02-003","owasp":"A02:2025 Security Misconfiguration","name":"Tomcat 기본페이지 노출","url":"/"},
    {"check_id":"WEB-A02-004","owasp":"A02:2025 Security Misconfiguration","name":"민감정보 노출","url":"/vulnapp/debug.jsp"},
    {"check_id":"WEB-A03-001","owasp":"A03:2025 Software Supply Chain Failures","name":"취약한 Log4j 사용","url":"/vulnapp/log4j"},
    {"check_id":"WEB-A03-002","owasp":"A03:2025 Software Supply Chain Failures","name":"구버전 jQuery 사용","url":"/vulnapp/static/js/jquery-1.12.4.min.js"},
    {"check_id":"WEB-A04-001","owasp":"A04:2025 Cryptographic Failures","name":"HTTPS 미적용","url":"/"},
    {"check_id":"WEB-A04-002","owasp":"A04:2025 Cryptographic Failures","name":"쿠키 Secure/HttpOnly 미설정","url":"/vulnapp/login.jsp"},
    {"check_id":"WEB-A05-001","owasp":"A05:2025 Injection","name":"SQL Injection","url":"/vulnapp/login.jsp"},
    {"check_id":"WEB-A05-002","owasp":"A05:2025 Injection","name":"Reflected XSS","url":"/vulnapp/search.jsp"},
    {"check_id":"WEB-A05-003","owasp":"A05:2025 Injection","name":"Stored XSS","url":"/vulnapp/board.jsp"},
    {"check_id":"WEB-A05-004","owasp":"A05:2025 Injection","name":"Command Injection","url":"/vulnapp/ping.jsp?host="},
    {"check_id":"WEB-A05-005","owasp":"A05:2025 Injection","name":"Local File Inclusion","url":"/vulnapp/download.jsp?file="},
    {"check_id":"WEB-A06-001","owasp":"A06:2025 Insecure Design","name":"로그인 Rate Limit 미구현","url":"/vulnapp/login.jsp"},
    {"check_id":"WEB-A06-002","owasp":"A06:2025 Insecure Design","name":"debug=true 기능 활성화","url":"/vulnapp/?debug=true"},
    {"check_id":"WEB-A07-001","owasp":"A07:2025 Authentication Failures","name":"계정 잠금 미구현","url":"/vulnapp/login.jsp"},
    {"check_id":"WEB-A07-002","owasp":"A07:2025 Authentication Failures","name":"약한 비밀번호 허용","url":"/vulnapp/register.jsp"},
    {"check_id":"WEB-A07-003","owasp":"A07:2025 Authentication Failures","name":"JWT 검증 우회","url":"/vulnapp/api/profile"},
    {"check_id":"WEB-A08-001","owasp":"A08:2025 Software or Data Integrity Failures","name":"웹쉘 업로드 가능","url":"/vulnapp/upload.jsp"},
    {"check_id":"WEB-A09-001","owasp":"A09:2025 Logging & Alerting Failures","name":"로그인 실패 로그 미기록","url":"/vulnapp/logs/security.log"},
    {"check_id":"WEB-A09-002","owasp":"A09:2025 Logging & Alerting Failures","name":"관리자 행위 로그 미기록","url":"/vulnapp/logs/security.log"},
    {"check_id":"WEB-A10-001","owasp":"A10:2025 Mishandling of Exceptional Conditions","name":"Stack Trace 노출","url":"/vulnapp/error.jsp"},
    {"check_id":"WEB-A10-002","owasp":"A10:2025 Mishandling of Exceptional Conditions","name":"SSRF","url":"/vulnapp/fetch.jsp?url="}
]

app = FastAPI(title="Auto Scanner API")


class ScanRequest(BaseModel):
    target: str = Field(..., description="진단 대상 URL")
    tomcat_port: int = Field(default=8080, description="Tomcat 직접 접근 포트")
    timeout: int = Field(default=5, description="HTTP 요청 타임아웃")
    normal_user_credentials: str | None = Field(
        default=None,
        description="일반 사용자 계정 후보. 형식: id:pw,id2:pw2"
    )
    model: str = Field(
        default=os.getenv("OPENAI_MODEL", "gpt-5.5"),
        description="OpenAI 모델명"
    )
    evidence_output: str = Field(default="outputs/gpt_evidence.json")
    initial_output: str = Field(default="outputs/gpt_initial_assessment.json")
    output: str = Field(default="outputs/gpt_analysis_results.json")
    excel_output: str = Field(default="outputs/자동진단.xlsx")
    rule_output: str = Field(default="outputs/rule/scan_result.json")
    rule_sqlmap: bool = Field(default=True)
    download: bool = Field(default=True, description="false면 JSON 응답, 기본은 엑셀 파일 다운로드")

def make_scan_id():
    return "SCAN-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def now_utc():
    return datetime.now(KST).strftime("%Y-%m-%dT%H:%M:%S+09:00")


def get_check_catalog_text():
    lines = []
    for item in CHECK_CATALOG:
        lines.append(
            f"- {item['name']}: {item['check_id']} / {item['owasp']}"
        )
    return "\n".join(lines)


def save_json(path: str, data: dict):
    """
    기존 파일이 있어도 새 파일명을 만들지 않고 그대로 덮어쓴다.
    """
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_request_output_path(path_value: str, request_id: str) -> str:
    output_path = Path(path_value)
    parent = output_path.parent
    stem = output_path.stem
    suffix = output_path.suffix
    return str(parent / f"{stem}_{request_id}{suffix}")


def parse_normal_user_credentials(raw_value: str | None) -> list[dict]:
    raw = raw_value or os.getenv("NORMAL_USER_CREDENTIALS", "")
    credentials = []

    if raw.strip():
        for chunk in raw.split(","):
            if ":" not in chunk:
                continue
            username, password = chunk.split(":", 1)
            username = username.strip()
            password = password.strip()
            if username and password:
                credentials.append({
                    "username": username,
                    "password": password
                })

    if credentials:
        return credentials

    return [
        {"username": "user", "password": "user123"},
        {"username": "guest", "password": "guest123"},
        {"username": "member", "password": "member123"},
        {"username": "test", "password": "test123"},
    ]


def run_signature_scan(target: str, output_path: str, run_sqlmap: bool = False):
    current_dir = Path(__file__).resolve().parent
    rule_path = current_dir / "rule.py"

    if not rule_path.exists():
        raise FileNotFoundError(f"rule.py not found: {rule_path}")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(rule_path), target, "-o", str(output)]

    if run_sqlmap:
        cmd.append("--sqlmap")

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(current_dir)
    )

    if proc.returncode != 0:
        raise RuntimeError(
            "rule.py execution failed\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )

    if not output.exists():
        raise FileNotFoundError(f"rule.py output not found: {output}")

    return load_json(str(output)), str(output)


def run_excel_export(input_path: str, output_path: str):
    current_dir = Path(__file__).resolve().parent
    exporter_path = current_dir / "make_excel_file.py"

    if not exporter_path.exists():
        raise FileNotFoundError(f"make_excel_file.py not found: {exporter_path}")

    cmd = [
        sys.executable,
        str(exporter_path),
        "--input",
        input_path,
        "--output",
        output_path,
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(current_dir)
    )

    if proc.returncode != 0:
        raise RuntimeError(
            "make_excel_file.py execution failed\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )

    return proc.stdout.strip()


def format_sqlmap_summary(sqlmap_data):
    if not isinstance(sqlmap_data, dict):
        return None

    if sqlmap_data.get("error"):
        return f"sqlmap 보조 점검 결과: {sqlmap_data['error']}"

    parts = []

    dbms_banner = sqlmap_data.get("dbms_banner")
    current_user = sqlmap_data.get("current_user")
    current_db = sqlmap_data.get("current_db")
    is_dba = sqlmap_data.get("is_dba")
    databases = sqlmap_data.get("databases")

    if dbms_banner:
        parts.append(f"DBMS 배너는 {dbms_banner}로 식별됨")
    if current_user:
        parts.append(f"DB 현재 사용자는 {current_user}로 확인됨")
    if current_db:
        parts.append(f"current database() 값은 {current_db}로 확인됨")
    if isinstance(is_dba, bool):
        parts.append(
            "현재 DB 계정은 DBA 권한으로 식별됨"
            if is_dba else
            "현재 DB 계정은 DBA 권한으로 식별되지 않음"
        )
    if isinstance(databases, list) and databases:
        parts.append(
            "열거된 데이터베이스는 "
            + ", ".join(str(db) for db in databases)
            + " 임"
        )

    if not parts:
        return None

    return "sqlmap 보조 점검 결과: " + ". ".join(parts) + "."


def format_signature_evidence_text(evidence):
    if isinstance(evidence, str):
        return evidence.strip()

    if not isinstance(evidence, dict):
        return str(evidence).strip()

    parts = []

    for key in ["payload", "error_based", "auth_bypass", "time_based", "delay"]:
        value = evidence.get(key)
        if value is None:
            continue
        parts.append(f"{key}={value}")

    sqlmap_summary = format_sqlmap_summary(evidence.get("sqlmap"))
    if sqlmap_summary:
        parts.append(sqlmap_summary)

    if parts:
        return ", ".join(parts)

    return str(evidence).strip()


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

    sqlmap_summary = format_sqlmap_summary(evidence.get("sqlmap"))
    if sqlmap_summary:
        summarized["sqlmap_summary"] = sqlmap_summary

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


def sanitize_url_to_path(url_value: str | None):
    raw = str(url_value or "").strip()
    if not raw:
        return ""

    parsed = urlparse(raw)
    path = parsed.path or ""

    if not path:
        path = raw.split("?", 1)[0].split("#", 1)[0].strip()

    return path or "/"


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
            "url": item.get("url"),
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


def merge_signature_findings(final_report: dict, signature_report: dict | None):
    if not signature_report:
        return final_report

    merged_results = []
    signature_by_check_id = {
        item.get("check_id"): item
        for item in signature_report.get("results", [])
        if item.get("check_id")
    }

    seen_check_ids = set()

    for item in final_report.get("results", []):
        merged_item = dict(item)
        check_id = merged_item.get("check_id")
        signature_item = signature_by_check_id.get(check_id)

        if signature_item:
            seen_check_ids.add(check_id)
            signature_evidence = format_signature_evidence_text(
                signature_item.get("evidence", "")
            )

            if signature_evidence and signature_evidence not in merged_item.get("evidence", ""):
                merged_item["evidence"] = (
                    f"{merged_item.get('evidence', '').strip()} "
                    f"시그니처 기반 추가 근거: {signature_evidence}"
                ).strip()

        merged_results.append(merged_item)

    for signature_item in signature_report.get("results", []):
        check_id = signature_item.get("check_id")
        if not check_id or check_id in seen_check_ids:
            continue

        merged_results.append({
            "id": "",
            "check_id": check_id,
            "owasp": force_owasp_2025(str(signature_item.get("owasp", "")).strip()),
            "name": str(signature_item.get("name", "")).strip(),
            "url": str(signature_item.get("url", "")).strip(),
            "severity": str(signature_item.get("severity", "low")).lower(),
            "evidence": (
                "rule.py 시그니처 기반 자동 진단 결과: "
                f"{format_signature_evidence_text(signature_item.get('evidence', ''))}"
            ).strip(),
            "recommendation": str(signature_item.get("recommendation", "")).strip()
        })

    final_report["results"] = normalize_results(merged_results)
    final_report["summary"] = build_summary(final_report["results"])
    return final_report


def complete_report_with_catalog(
    final_report: dict,
    initial_report: dict | None,
    signature_report: dict | None
):
    final_by_check_id = {
        item.get("check_id"): dict(item)
        for item in final_report.get("results", [])
        if item.get("check_id")
    }
    initial_by_check_id = {
        item.get("check_id"): item
        for item in (initial_report or {}).get("assessments", [])
        if item.get("check_id")
    }
    signature_by_check_id = {
        item.get("check_id"): item
        for item in (signature_report or {}).get("results", [])
        if item.get("check_id")
    }

    completed_results = []

    for check in CHECK_CATALOG:
        check_id = check["check_id"]
        item = final_by_check_id.get(check_id)

        if item:
            item["check_id"] = check_id
            item["owasp"] = check["owasp"]
            item["name"] = check["name"]
            item["url"] = item.get("url") or check["url"]
            completed_results.append(item)
            continue

        initial_item = initial_by_check_id.get(check_id)
        signature_item = signature_by_check_id.get(check_id)

        if signature_item:
            completed_results.append({
                "id": "",
                "check_id": check_id,
                "owasp": check["owasp"],
                "name": check["name"],
                "url": check["url"],
                "severity": str(signature_item.get("severity", "low")).lower(),
                "evidence": (
                    "rule.py 시그니처 기반 자동 진단 결과: "
                    f"{format_signature_evidence_text(signature_item.get('evidence', ''))}"
                ).strip(),
                "recommendation": str(signature_item.get("recommendation", "")).strip()
            })
            continue

        if initial_item:
            initial_result = str(initial_item.get("result", "")).strip()
            if initial_result == "양호":
                completed_results.append({
                    "id": "",
                    "check_id": check_id,
                    "owasp": check["owasp"],
                    "name": check["name"],
                    "url": check["url"],
                    "severity": "pass",
                    "evidence": str(initial_item.get("evidence", "")).strip() or "수집된 근거에서 해당 항목은 적절히 방어된 것으로 판단됨.",
                    "recommendation": str(initial_item.get("recommendation", "")).strip() or "현재 수집 범위에서는 추가 조치가 필요하지 않으며 동일 수준의 방어 상태를 유지할 것."
                })
                continue

            if initial_result in ["N/A", "보류"]:
                completed_results.append({
                    "id": "",
                    "check_id": check_id,
                    "owasp": check["owasp"],
                    "name": check["name"],
                    "url": check["url"],
                    "severity": "n/a",
                    "evidence": str(initial_item.get("evidence", "")).strip() or str(initial_item.get("defer_reason", "")).strip() or "수집된 근거만으로는 해당 취약점 존재 여부를 판단할 수 없음.",
                    "recommendation": str(initial_item.get("recommendation", "")).strip() or "추가 엔드포인트 확인, 인증 상태 점검, 수동 검증 등 보강 진단이 필요함."
                })
                continue

        completed_results.append({
            "id": "",
            "check_id": check_id,
            "owasp": check["owasp"],
            "name": check["name"],
            "url": check["url"],
            "severity": "n/a",
            "evidence": "수집된 근거와 rule.py 결과만으로는 해당 취약점의 존재 여부를 확인할 수 없음.",
            "recommendation": "추가 엔드포인트 확인, 인증 상태 점검, 수동 검증 등 보강 진단이 필요함."
        })

    final_report["results"] = normalize_results(completed_results)
    final_report["summary"] = build_summary(final_report["results"])
    return final_report


def normalize_results(results):
    normalized = []
    allowed_severities = {"critical", "high", "medium", "low", "pass", "n/a"}

    for idx, item in enumerate(results, start=1):
        severity = str(item.get("severity", "low")).lower()

        if severity not in allowed_severities:
            severity = "n/a"

        check_id = str(item.get("check_id", "")).strip()
        owasp = force_owasp_2025(str(item.get("owasp", "")).strip())

        normalized.append({
            "id": f"RES-{idx:04d}",
            "check_id": check_id,
            "owasp": owasp,
            "name": str(item.get("name", "")).strip(),
            "url": sanitize_url_to_path(item.get("url")),
            "severity": severity,
            "evidence": str(item.get("evidence", "")).strip(),
            "recommendation": str(item.get("recommendation", "")).strip()
        })

    return normalized


def build_summary(results):
    severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "pass": 0,
        "n/a": 0
    }

    for item in results:
        sev = item.get("severity")
        if sev in severity:
            severity[sev] += 1

    return {
        "total": len(results),
        "severity": severity
    }


def build_admin_access_override(evidence: dict):
    collected = evidence.get("collected_evidence", {})
    anonymous = collected.get("admin_page", {})
    authenticated = collected.get("admin_page_as_authenticated_user", {})
    admin_response = authenticated.get("admin_response", {})
    signature_hints = admin_response.get("signature_hints", {})

    if not signature_hints.get("access_granted_to_non_admin"):
        return None

    username = authenticated.get("credential_label", "일반 사용자")
    anonymous_status = anonymous.get("status_code")
    anonymous_location = anonymous.get("redirect_location", "")
    admin_status = admin_response.get("status_code")

    evidence_text = (
        f"미로그인 상태에서 /vulnapp/admin.jsp 접근 시 HTTP {anonymous_status}"
        f"{f', Location: {anonymous_location}' if anonymous_location else ''} 로 로그인 페이지로 이동했으나, "
        f"일반 사용자 계정 {username} 로그인 후 동일 경로 요청이 HTTP {admin_status}로 응답했다. "
        "비관리자 세션에서도 관리자 페이지가 노출되어 권한 검증 우회로 판단된다."
    )

    return {
        "check_id": "WEB-A01-001",
        "owasp": "A01:2025 Broken Access Control",
        "name": "관리자 페이지 직접 접근",
        "url": "/vulnapp/admin.jsp",
        "severity": "medium",
        "evidence": evidence_text,
        "recommendation": "관리자 페이지에 대해 인증뿐 아니라 서버 측 역할(Role) 기반 권한 검증을 적용하고 비관리자 계정은 403으로 차단"
    }


def apply_evidence_overrides(report: dict, evidence: dict):
    override = build_admin_access_override(evidence)

    if not override:
        return report

    updated = False

    for item in report.get("results", []):
        if item.get("check_id") != override["check_id"]:
            continue
        item.update(override)
        updated = True
        break

    if not updated:
        report.setdefault("results", []).append(override)

    report["results"] = normalize_results(report.get("results", []))
    report["summary"] = build_summary(report["results"])
    return report


class ExternalEvidenceCollector:
    """
    외부 진단 PC에서 대상 웹서비스에 HTTP 요청을 보내
    GPT 분석에 필요한 응답 헤더, 상태코드, 본문 샘플, 테스트 요청 결과를 수집한다.

    이 클래스는 최종 취약 여부를 확정하지 않고,
    GPT가 1차 판단할 수 있도록 관찰 가능한 evidence를 모은다.
    """

    def __init__(
        self,
        target: str,
        tomcat_port: int = 8080,
        timeout: int = 5,
        normal_user_credentials: str | None = None
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.tomcat_port = tomcat_port
        self.normal_user_credentials = parse_normal_user_credentials(
            normal_user_credentials
        )

        parsed = urlparse(self.target)
        self.scheme = parsed.scheme or "http"
        self.host = parsed.hostname

        if not self.host:
            raise ValueError("target 형식이 올바르지 않습니다. 예: http://15.164.60.79")

    def extract_login_form(self):
        login_url = self.target + "/vulnapp/login.jsp"
        res = self.safe_request("GET", login_url)

        if isinstance(res, dict):
            return None

        soup = BeautifulSoup(res.text, "html.parser")
        form = soup.find("form")

        if not form:
            return None

        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        params = []

        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            input_type = input_tag.get("type", "text")

            if name:
                params.append({
                    "name": name,
                    "type": input_type
                })

        return {
            "url": login_url,
            "action": urljoin(login_url, action),
            "method": method,
            "params": params
        }

    def build_login_payload(self, form: dict, username: str, password: str):
        payload = {}

        for param in form.get("params", []):
            name = str(param.get("name", ""))
            input_type = str(param.get("type", "text")).lower()
            lowered_name = name.lower()

            if input_type == "submit":
                continue

            if lowered_name in ["id", "user", "userid", "user_id", "username", "loginid"]:
                payload[name] = username
            elif lowered_name in ["pw", "password", "passwd", "userpw", "user_pw"]:
                payload[name] = password
            elif input_type in ["text", "email", "search"] and name not in payload:
                payload[name] = username
            elif input_type == "password":
                payload[name] = password
            else:
                payload[name] = param.get("value", "") or "test"

        return payload

    def is_login_success(self, response):
        if isinstance(response, dict):
            return False

        location = response.headers.get("Location", "").lower()
        body = response.text.lower()

        if response.status_code in [301, 302, 303, 307, 308]:
            if "login.jsp" in location:
                return False
            if any(keyword in location for keyword in ["/vulnapp/", "index.jsp", "profile", "mypage", "admin.jsp"]):
                return True

        return (
            "logout" in body or
            "mypage" in body or
            "welcome" in body or
            "환영" in body or
            ("login" not in body and "로그인" not in body)
        )

    def build_session(self):
        session = requests.Session()
        session.headers.update(HEADERS)
        return session

    def safe_request(self, method: str, url: str, session=None, **kwargs):
        request_session = session or self.build_session()
        should_close = session is None

        try:
            return request_session.request(
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
        finally:
            if should_close:
                request_session.close()

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
        res = self.safe_request("GET", url, allow_redirects=False)
        result = self.response_to_dict(res, body_limit=1200)

        if not isinstance(res, dict):
            result["redirect_location"] = res.headers.get("Location", "")

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

    def collect_admin_page_as_authenticated_user(self):
        form = self.extract_login_form()

        if not form:
            return {
                "attempted": False,
                "reason": "login_form_not_found"
            }

        for credential in self.normal_user_credentials:
            session = self.build_session()

            try:
                username = credential["username"]
                payload = self.build_login_payload(
                    form=form,
                    username=username,
                    password=credential["password"]
                )

                login_res = self.safe_request(
                    form["method"],
                    form["action"],
                    session=session,
                    data=payload if form["method"] == "POST" else None,
                    params=payload if form["method"] != "POST" else None,
                    allow_redirects=False
                )

                login_result = self.response_to_dict(login_res, body_limit=800)
                login_result["credential_label"] = username
                login_result["login_success"] = self.is_login_success(login_res)

                admin_url = self.target + "/vulnapp/admin.jsp"
                admin_res = self.safe_request(
                    "GET",
                    admin_url,
                    session=session,
                    allow_redirects=False
                )
                admin_result = self.response_to_dict(admin_res, body_limit=1200)

                if not isinstance(admin_res, dict):
                    admin_result["redirect_location"] = admin_res.headers.get("Location", "")
                    admin_body = admin_res.text.lower()
                    admin_result["signature_hints"] = {
                        "contains_admin_keywords": any(
                            keyword in admin_body
                            for keyword in [
                                "admin page",
                                "system config",
                                "user list",
                                "backup download",
                                "관리자"
                            ]
                        ),
                        "contains_login_keyword": "login" in admin_body or "로그인" in admin_body,
                        "access_granted_to_non_admin": (
                            login_result["login_success"] and
                            admin_res.status_code == 200 and
                            "login" not in admin_body and
                            "로그인" not in admin_body
                        )
                    }

                if (
                    login_result.get("login_success") and
                    not isinstance(admin_res, dict)
                ):
                    return {
                        "attempted": True,
                        "credential_label": username,
                        "login_request": {
                            "url": form["action"],
                            "method": form["method"],
                            "submitted_fields": sorted(payload.keys())
                        },
                        "login_response": login_result,
                        "admin_response": admin_result
                    }
            finally:
                session.close()

        return {
            "attempted": True,
            "login_success": False,
            "tested_credentials": [
                item["username"]
                for item in self.normal_user_credentials
            ]
        }

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
        session = self.build_session()

        try:
            for _ in range(8):
                res = self.safe_request(
                    "POST",
                    url,
                    session=session,
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
        finally:
            session.close()

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
        session = self.build_session()

        try:
            for _ in range(10):
                res = self.safe_request(
                    "POST",
                    url,
                    session=session,
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
        finally:
            session.close()

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
            "/vulnapp/download.jsp?filename=test.txt",
            "/vulnapp/profile.jsp?user_idx=1",
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
                "admin_page_as_authenticated_user": self.collect_admin_page_as_authenticated_user(),
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
9. upload.jsp, board.jsp, download.jsp, profile.jsp, ping.jsp, register.jsp, api/profile 등 존재가 확인되지 않은 엔드포인트 취약점은 생성하지 마라.
10. evidence에는 어떤 응답, 상태코드, 헤더, 본문 샘플, 테스트 반응이 근거인지 구체적으로 작성하라.
11. 아래 권장 check_id 목록의 모든 항목을 assessments에 반드시 1개씩 포함하라.
12. severity는 critical, high, medium, low, pass, n/a 중 하나로 작성하라.
13. result가 양호이면 severity는 pass로 작성하라.
14. result가 N/A 또는 보류이면 severity는 n/a로 작성하라.
15. url에는 해당 취약점이 발생하거나 점검된 대표 경로를 넣어라. 예: /vulnapp/login.jsp
16. confidence는 High, Medium, Low 중 하나로 작성하라.
17. 출력은 반드시 JSON 형식이어야 한다.

권장 check_id 및 OWASP 2025 매핑:
{get_check_catalog_text()}

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
                                        "url": {"type": "string"},
                                        "result": {
                                            "type": "string",
                                            "enum": ["취약", "미흡", "양호", "N/A", "보류"]
                                        },
                                        "severity": {
                                            "type": "string",
                                            "enum": ["critical", "high", "medium", "low", "pass", "n/a"]
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
                                        "url",
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
6. 아래 권장 check_id 목록의 모든 항목을 results에 반드시 1개씩 포함하라.
7. OWASP는 반드시 2025 기준으로 작성하라. "2021"이라는 문자열은 절대 출력하지 마라.
8. OWASP 형식은 반드시 "A01:2025 Broken Access Control"처럼 연도 뒤에 공백을 사용하라.
9. check_id는 반드시 WEB-Axx-xxx 형식으로 작성하라. 예: WEB-A01-001
10. ADMIN_DIRECT_ACCESS, SQL_INJECTION, SECURITY_HEADERS 같은 임의 문자열 check_id는 사용하지 마라.
11. upload.jsp, board.jsp, download.jsp, profile.jsp, ping.jsp, register.jsp, api/profile 등 존재가 확인되지 않은 엔드포인트 취약점은 생성하지 마라.
12. 잘 방어된 항목은 severity를 pass로 작성하라.
13. 수집 근거가 부족하거나 판단할 수 없으면 severity를 n/a로 작성하라.
14. 취약점이 확인된 항목만 critical, high, medium, low 중 하나를 사용하라.
15. evidence에는 pass 또는 n/a 판단의 이유도 분명히 적어라.
16. url에는 해당 취약점이 발생하거나 점검된 대표 경로를 넣어라. 예: /vulnapp/login.jsp
17. results의 id는 RES-0001부터 순서대로 작성하라.
18. summary.total은 results 개수와 같아야 한다.
19. summary.severity는 results의 severity 개수를 집계한 값이어야 한다.
20. 출력은 반드시 JSON 형식이어야 한다.
21. 공격 절차를 자세히 설명하지 말고, 방어적 진단 결과와 조치 중심으로 작성하라.
22. SQL Injection(WEB-A05-001)에서 signature_based_report 안의 sqlmap_summary, current_db, databases, dbms_banner, current_user 정보가 있으면 evidence에 자연스러운 문장으로 반드시 반영하라.

메타데이터:
scan_id: {scan_id}
target: {target}
scanner: auto-scan
generated_at: {generated_at}

권장 check_id 및 OWASP 2025 매핑:
{get_check_catalog_text()}

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
                                "enum": ["auto-scan"]
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
                                            "low": {"type": "integer"},
                                            "pass": {"type": "integer"},
                                            "n/a": {"type": "integer"}
                                        },
                                        "required": [
                                            "critical",
                                            "high",
                                            "medium",
                                            "low",
                                            "pass",
                                            "n/a"
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
                                        "url": {"type": "string"},
                                        "severity": {
                                            "type": "string",
                                            "enum": [
                                                "critical",
                                                "high",
                                                "medium",
                                                "low",
                                                "pass",
                                                "n/a"
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
                                        "url",
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
        report["scanner"] = "auto-scan"
        report["generated_at"] = generated_at

        report["results"] = normalize_results(report.get("results", []))
        report["summary"] = build_summary(report["results"])

        return report

    def normalize_results(self, results):
        return normalize_results(results)

    def build_summary(self, results):
        return build_summary(results)


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
    print(f"Pass: {severity['pass']}")
    print(f"N/A: {severity['n/a']}")
    print("============================================\n")

    for finding in report["results"]:
        print(
            f"[{finding['id']}] {finding['name']} "
            f"({finding['check_id']}) / Severity: {finding['severity']}"
        )
        print(f"  URL: {finding['url']}")
        print(f"  OWASP: {finding['owasp']}")
        print(f"  근거: {finding['evidence']}")
        print(f"  대응: {finding['recommendation']}")
        print()


def execute_scan(
    target: str,
    tomcat_port: int = 8080,
    timeout: int = 5,
    model: str | None = None,
    evidence_output: str = "outputs/gpt_evidence.json",
    initial_output: str = "outputs/gpt_initial_assessment.json",
    output: str = "outputs/gpt_analysis_results.json",
    excel_output: str = "outputs/자동진단.xlsx",
    rule_output: str = "outputs/rule/scan_result.json",
    rule_sqlmap: bool = True,
    verbose: bool = False,
):
    requests.packages.urllib3.disable_warnings()

    def log(message: str):
        if verbose:
            print(message)

    log("[1] rule.py 시그니처 기반 스캔 실행 중...")

    try:
        signature_report, signature_path = run_signature_scan(
            target=target,
            output_path=rule_output,
            run_sqlmap=rule_sqlmap
        )
        log(f"[+] rule.py 실행 완료: {signature_path}")
    except Exception as exc:
        signature_report = None
        signature_path = None
        log(f"[!] rule.py 실행 실패: {exc}")
        log("[!] GPT evidence 기반으로만 분석합니다.")

    log("[2] 외부에서 웹서비스 응답 데이터 수집 중...")

    collector = ExternalEvidenceCollector(
        target=target,
        tomcat_port=tomcat_port,
        timeout=timeout
    )

    evidence = collector.collect_all()
    save_json(evidence_output, evidence)
    log(f"[+] 수집 증거 저장 완료: {evidence_output}")

    if signature_report:
        log(f"[+] signature-based 결과 로드 완료: {signature_path}")
    else:
        log("[!] signature-based 결과가 없어 GPT evidence 기반으로만 분석합니다.")

    analyzer = GPTVulnerabilityAnalyzer(
        model=model or os.getenv("OPENAI_MODEL", "gpt-5.5")
    )

    log("[3] GPT 1차 판단 중...")
    initial_report = analyzer.initial_analyze(evidence)
    save_json(initial_output, initial_report)
    log(f"[+] GPT 1차 판단 결과 저장 완료: {initial_output}")

    log("[4] GPT 최종 판단 중...")
    report = analyzer.final_analyze(
        evidence=evidence,
        initial_report=initial_report,
        signature_report=signature_report
    )
    report = merge_signature_findings(report, signature_report)
    report = complete_report_with_catalog(report, initial_report, signature_report)

    save_json(output, report)
    log(f"[+] GPT 최종 분석 결과 저장 완료: {output}")

    excel_message = ""

    try:
        excel_message = run_excel_export(
            input_path=output,
            output_path=excel_output
        )
        if excel_message:
            log(excel_message)
    except Exception as exc:
        log(f"[!] Excel 파일 생성 실패: {exc}")

    return {
        "report": report,
        "evidence_path": evidence_output,
        "initial_output_path": initial_output,
        "output_path": output,
        "excel_output_path": excel_output,
        "rule_output_path": signature_path or rule_output,
        "excel_message": excel_message,
        "signature_scan_succeeded": signature_report is not None,
    }


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan")
def scan(payload: ScanRequest):
    try:
        request_id = datetime.now(KST).strftime("%Y%m%d-%H%M%S-%f")
        result = execute_scan(
            target=payload.target,
            tomcat_port=payload.tomcat_port,
            timeout=payload.timeout,
            model=payload.model,
            evidence_output=build_request_output_path(payload.evidence_output, request_id),
            initial_output=build_request_output_path(payload.initial_output, request_id),
            output=build_request_output_path(payload.output, request_id),
            excel_output=build_request_output_path(payload.excel_output, request_id),
            rule_output=build_request_output_path(payload.rule_output, request_id),
            rule_sqlmap=payload.rule_sqlmap,
            verbose=False,
        )
        excel_path = Path(result["excel_output_path"])

        if not excel_path.exists():
            raise HTTPException(status_code=500, detail="Excel file was not created")

        if payload.download:
            return FileResponse(
                path=str(excel_path),
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                filename="자동진단.xlsx",
            )

        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def main():
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

    parser.add_argument(
        "--excel-output",
        default="outputs/자동진단.xlsx",
        help="최종 분석 결과 Excel 파일 저장 경로"
    )

    parser.add_argument(
        "--rule-output",
        default="outputs/rule/scan_result.json",
        help="rule.py 시그니처 기반 결과 저장 파일"
    )

    parser.add_argument(
        "--rule-sqlmap",
        dest="rule_sqlmap",
        action="store_true",
        help="rule.py 실행 시 sqlmap 기반 보조 점검 활성화"
    )

    parser.add_argument(
        "--no-rule-sqlmap",
        dest="rule_sqlmap",
        action="store_false",
        help="rule.py 실행 시 sqlmap 기반 보조 점검 비활성화"
    )

    parser.set_defaults(rule_sqlmap=True)

    args = parser.parse_args()
    result = execute_scan(
        target=args.target,
        tomcat_port=args.tomcat_port,
        timeout=args.timeout,
        model=args.model,
        evidence_output=args.evidence_output,
        initial_output=args.initial_output,
        output=args.output,
        excel_output=args.excel_output,
        rule_output=args.rule_output,
        rule_sqlmap=args.rule_sqlmap,
        verbose=True,
    )
    print_report(result["report"])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=8000)
    else:
        main()
