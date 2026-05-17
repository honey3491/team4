import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from openai import OpenAI
from pydantic import BaseModel, Field


load_dotenv()

HEADERS = {"User-Agent": "4AKDA-GPT-Based-Scanner/3.3"}
KST = timezone(timedelta(hours=9))
NORMAL_USER_ID = os.getenv("SCANNER_NORMAL_USER_ID", "user1")
NORMAL_USER_PW = os.getenv("SCANNER_NORMAL_USER_PW", "user1234")

CHECK_CATALOG = [
    {"check_id": "WEB-A01-001", "owasp": "A01:2025 Broken Access Control", "name": "관리자 페이지 직접 접근", "url": "/vulnapp/admin.jsp"},
    {"check_id": "WEB-A01-002", "owasp": "A01:2025 Broken Access Control", "name": "IDOR", "url": "/vulnapp/profile.jsp?user_idx="},
    {"check_id": "WEB-A02-001", "owasp": "A02:2025 Security Misconfiguration", "name": "보안 헤더 미설정", "url": "/vulnapp/"},
    {"check_id": "WEB-A02-002", "owasp": "A02:2025 Security Misconfiguration", "name": "서버 버전 노출", "url": "/, :8080/"},
    {"check_id": "WEB-A02-003", "owasp": "A02:2025 Security Misconfiguration", "name": "Tomcat 기본페이지 노출", "url": ":8080/"},
    {"check_id": "WEB-A02-004", "owasp": "A02:2025 Security Misconfiguration", "name": "debug=true 기능 활성화", "url": "/vulnapp/debug.jsp"},
    {"check_id": "WEB-A03-001", "owasp": "A03:2025 Software Supply Chain Failures", "name": "취약한 Log4j 사용", "url": "N/A"},
    {"check_id": "WEB-A03-002", "owasp": "A03:2025 Software Supply Chain Failures", "name": "구버전 jQuery 사용", "url": "N/A"},
    {"check_id": "WEB-A04-001", "owasp": "A04:2025 Cryptographic Failures", "name": "HTTPS 미적용", "url": "/vulnapp/"},
    {"check_id": "WEB-A04-002", "owasp": "A04:2025 Cryptographic Failures", "name": "쿠키 Secure/HttpOnly 미설정", "url": "/vulnapp/login.jsp"},
    {"check_id": "WEB-A05-001", "owasp": "A05:2025 Injection", "name": "SQL Injection", "url": "/vulnapp/login.jsp"},
    {"check_id": "WEB-A05-002", "owasp": "A05:2025 Injection", "name": "Reflected XSS", "url": "/vulnapp/search.jsp?keyword="},
    {"check_id": "WEB-A05-003", "owasp": "A05:2025 Injection", "name": "Stored XSS", "url": "/vulnapp/upload.jsp"},
    {"check_id": "WEB-A05-004", "owasp": "A05:2025 Injection", "name": "Command Injection", "url": "/vulnapp/ping.jsp?host="},
    {"check_id": "WEB-A06-001", "owasp": "A06:2025 Insecure Design", "name": "로그인 Rate Limit 미구현", "url": "/vulnapp/login.jsp"},
    {"check_id": "WEB-A07-001", "owasp": "A07:2025 Authentication Failures", "name": "계정 잠금 미구현", "url": "/vulnapp/login.jsp"},
    {"check_id": "WEB-A07-002", "owasp": "A07:2025 Authentication Failures", "name": "약한 비밀번호 허용", "url": "/vulnapp/register.jsp"},
    {"check_id": "WEB-A07-003", "owasp": "A07:2025 Authentication Failures", "name": "JWT 검증 우회", "url": "N/A"},
    {"check_id": "WEB-A08-001", "owasp": "A08:2025 Software or Data Integrity Failures", "name": "웹쉘 업로드 가능", "url": "/vulnapp/upload.jsp"},
    {"check_id": "WEB-A10-001", "owasp": "A10:2025 Mishandling of Exceptional Conditions", "name": "Stack Trace 노출", "url": "/vulnapp/profile.jsp?user_idx=abc"},
    {"check_id": "WEB-A10-002", "owasp": "A10:2025 Mishandling of Exceptional Conditions", "name": "SSRF", "url": "/vulnapp/fetch.jsp?url="},
]

# 수동진단 결과가 확보된 항목의 위험도 기준.
# - 빈 값/보류 항목은 포함하지 않는다.
# - 자동진단이 취약 또는 N/A로 확인된 경우, GPT가 과도하게 high로 판단하지 않도록
#   프로젝트 수동진단표 기준 severity로 보정한다.
MANUAL_CALIBRATED_SEVERITY = {
    "WEB-A01-001": "medium",
    "WEB-A01-002": "high",
    "WEB-A02-001": "low",
    "WEB-A02-002": "low",
    "WEB-A02-003": "medium",
    "WEB-A02-004": "medium",
    "WEB-A03-001": "n/a",
    "WEB-A03-002": "n/a",
    "WEB-A04-001": "medium",
    "WEB-A04-002": "medium",
    "WEB-A05-001": "high",
    "WEB-A05-002": "medium",
    "WEB-A06-001": "medium",
    "WEB-A07-001": "medium",
    "WEB-A07-003": "n/a",
}

# 수동진단에서 사이트 오류/미구현 때문에 판단 보류로 남긴 항목.
# 이 항목들은 rule.py가 pending 근거를 찾으면 GPT의 pass/n/a/low 판단보다 pending을 우선한다.
MANUAL_PENDING_CHECKS = {
    "WEB-A05-003",  # 게시글 상세 조회 404로 Stored XSS 재조회 검증 불가
    "WEB-A05-004",  # ping.jsp 404
    "WEB-A07-002",  # register.jsp 404
    "WEB-A08-001",  # shell.jsp 업로드 500 + uploads 경로 404
    "WEB-A10-001",  # DB 오류 노출로 원래 양호 항목 수정 후 재진단 필요
    "WEB-A10-002",  # fetch.jsp/internal/secret.jsp 404
}

SEVERITY_RANK = {"n/a": 0, "pending": 0, "pass": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


app = FastAPI(title="Auto Scanner API")


class ScanRequest(BaseModel):
    target: str = Field(..., description="진단 대상 URL")
    tomcat_port: int = Field(default=8080, description="Tomcat 직접 접근 포트")
    timeout: int = Field(default=5, description="HTTP 요청 타임아웃")
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


def run_signature_scan(target: str, output_path: str, run_sqlmap: bool = False, tomcat_port: int = 8080):
    current_dir = Path(__file__).resolve().parent
    rule_path = current_dir / "rule.py"

    if not rule_path.exists():
        raise FileNotFoundError(f"rule.py not found: {rule_path}")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(rule_path), target, "-o", str(output), "--tomcat-port", str(tomcat_port)]

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

    normalized_sqlmap = normalize_sqlmap_data(sqlmap_data)

    if normalized_sqlmap.get("error"):
        return f"sqlmap 보조 점검 결과: {sqlmap_data['error']}"

    parts = []

    dbms_banner = normalized_sqlmap.get("dbms_banner")
    current_user = normalized_sqlmap.get("current_user")
    current_db = normalized_sqlmap.get("current_db")
    is_dba = normalized_sqlmap.get("is_dba")
    databases = normalized_sqlmap.get("databases")

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


def normalize_sqlmap_data(sqlmap_data):
    if not isinstance(sqlmap_data, dict):
        return {}

    normalized = dict(sqlmap_data)
    raw_tail = str(normalized.get("raw_tail", "") or "")

    if raw_tail:
        if not normalized.get("dbms_banner"):
            dbms_match = re.search(r"back-end DBMS:\s*(.+)", raw_tail, re.IGNORECASE)
            banner_match = re.search(r"banner:\s*'([^']+)'", raw_tail, re.IGNORECASE)
            if dbms_match and banner_match:
                normalized["dbms_banner"] = f"{dbms_match.group(1).strip()} / banner={banner_match.group(1).strip()}"
            elif dbms_match:
                normalized["dbms_banner"] = dbms_match.group(1).strip()
            elif banner_match:
                normalized["dbms_banner"] = banner_match.group(1).strip()

        if not normalized.get("current_user"):
            current_user_match = re.search(r"current user:\s*'([^']+)'", raw_tail, re.IGNORECASE)
            if current_user_match:
                normalized["current_user"] = current_user_match.group(1).strip()

        if not normalized.get("current_db"):
            current_db_match = re.search(r"current database:\s*'([^']+)'", raw_tail, re.IGNORECASE)
            if current_db_match:
                normalized["current_db"] = current_db_match.group(1).strip()

        if normalized.get("is_dba") is None:
            is_dba_match = re.search(r"current user is DBA:\s*(True|False)", raw_tail, re.IGNORECASE)
            if is_dba_match:
                normalized["is_dba"] = is_dba_match.group(1).lower() == "true"

        if not normalized.get("databases"):
            databases_match = re.search(
                r"available databases \[\d+\]:\s*((?:\n\[\*\]\s*.+)+)",
                raw_tail,
                re.IGNORECASE,
            )
            if databases_match:
                normalized["databases"] = [
                    line.strip()[4:].strip()
                    for line in databases_match.group(1).splitlines()
                    if line.strip().startswith("[*]")
                ]

    return normalized


def format_evidence_text(evidence):
    if isinstance(evidence, str):
        return evidence.strip()

    if not isinstance(evidence, dict):
        return str(evidence).strip()

    parts = []

    payload = evidence.get("payload")
    if payload:
        parts.append(f"payload={payload}")

    redirect_location = evidence.get("redirect_location")
    if redirect_location:
        parts.append(f"redirect_location={redirect_location}")

    for key in ["error_based", "auth_bypass", "time_based", "delay"]:
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


def format_signature_evidence_text(evidence):
    return format_evidence_text(evidence)


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
            normalized_sqlmap = normalize_sqlmap_data(value)
            summarized["sqlmap"] = {
                "returncode": normalized_sqlmap.get("returncode"),
                "dbms_banner": normalized_sqlmap.get("dbms_banner"),
                "current_user": normalized_sqlmap.get("current_user"),
                "current_db": normalized_sqlmap.get("current_db"),
                "is_dba": normalized_sqlmap.get("is_dba"),
                "databases": normalized_sqlmap.get("databases"),
                "error": normalized_sqlmap.get("error")
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

            merged_item["severity"] = prefer_signature_severity(
                check_id,
                merged_item.get("severity"),
                signature_item.get("severity"),
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


def apply_manual_calibrated_severity(check_id: str, severity: str) -> str:
    """
    수동진단표와 자동진단 JSON 비교가 가능하도록 severity를 프로젝트 기준으로 보정한다.

    원칙:
    - 수동진단 결과가 확보된 항목만 보정한다.
    - 보류/미구현 항목은 보정하지 않는다.
    - pass로 확인된 항목은 취약 severity로 강제하지 않는다.
      단, WEB-A01-001은 일반 사용자 권한 우회가 rule.py 또는 evidence에서 확인되면
      merge 단계에서 medium으로 승격된다.
    - 취약으로 판단된 항목이 GPT에 의해 high로 과대평가된 경우, 수동진단 기준으로 낮춘다.
    """
    normalized = str(severity or "n/a").lower()
    target = MANUAL_CALIBRATED_SEVERITY.get(check_id)
    if not target:
        return normalized

    if target == "n/a":
        return "n/a"

    if normalized in {"high", "medium", "low"}:
        return target

    return normalized


def prefer_signature_severity(check_id: str, current_severity: str, signature_severity: str) -> str:
    """
    rule.py 결과와 GPT 결과를 병합할 때의 severity 우선순위.

    - rule.py가 pending을 반환하면 사이트 오류/미구현 때문에 수동진단도 보류한 항목이므로 pending을 우선한다.
    - GPT가 pass/n/a/pending으로 판단했지만 rule.py가 구체적인 취약 근거를 찾은 경우에는 rule.py 결과를 반영한다.
    - WEB-A08-001에서 JSP 업로드 실행이 확인되면 critical을 허용한다.
    """
    current = str(current_severity or "n/a").lower()
    sig = str(signature_severity or "n/a").lower()

    if sig == "pending":
        return "pending"

    if sig in {"critical", "high", "medium", "low"} and current in {"pass", "n/a", "pending"}:
        return sig

    return current

def normalize_results(results):
    normalized = []
    allowed_severities = {"critical", "high", "medium", "low", "pass", "n/a", "pending"}

    for idx, item in enumerate(results, start=1):
        severity = str(item.get("severity", "low")).lower()

        if severity not in allowed_severities:
            severity = "n/a"

        check_id = str(item.get("check_id", "")).strip()
        severity = apply_manual_calibrated_severity(check_id, severity)
        owasp = force_owasp_2025(str(item.get("owasp", "")).strip())

        normalized.append({
            "id": f"RES-{idx:04d}",
            "check_id": check_id,
            "owasp": owasp,
            "name": str(item.get("name", "")).strip(),
            "url": sanitize_url_to_path(item.get("url")),
            "severity": severity,
            "evidence": format_evidence_text(item.get("evidence", "")),
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
        "n/a": 0,
        "pending": 0
    }

    for item in results:
        sev = item.get("severity")
        if sev in severity:
            severity[sev] += 1

    return {
        "total": len(results),
        "severity": severity
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
            ("' OR '1'='1' -- ", "test"),
            ("admin' -- ", "test"),
            ("' OR 1=1 -- ", "test"),
        ]

        results = []
        url = self.target + "/vulnapp/login.jsp"

        for user_id, pw in payloads:
            # 로그인 우회 테스트는 세션 오염을 막기 위해 독립 세션을 사용한다.
            local_session = requests.Session()
            local_session.headers.update(HEADERS)
            try:
                res = local_session.post(
                    url,
                    data={"id": user_id, "pw": pw},
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False,
                )
            except requests.RequestException as e:
                results.append({"url": url, "error": str(e)})
                continue

            result = self.response_to_dict(res, body_limit=1200)
            result["test_type"] = "SQL Injection authentication bypass test"
            result["test_payload"] = {"id": user_id, "pw": pw}
            result["redirect_location"] = res.headers.get("Location", "")
            body = result.get("body_sample", "").lower()
            result["signature_hints"] = {
                "redirected_to_admin": res.status_code in [301, 302, 303, 307, 308] and "admin.jsp" in result["redirect_location"].lower(),
                "contains_logout": "logout" in body or "로그아웃" in body,
                "contains_admin": "admin" in body or "관리자" in body,
                "contains_sql_error": any(k in body for k in ["sql", "unknown column", "sqlexception", "mariadb"]),
            }
            results.append(result)

        return results

    def collect_xss_test(self):
        payloads = [
            "<script>alert(1337)</script>",
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ]

        results = []

        for payload in payloads:
            url = self.target + "/vulnapp/search.jsp?keyword=" + quote(payload)
            res = self.safe_request("GET", url)
            result = self.response_to_dict(res, body_limit=1600)
            result["test_type"] = "Reflected XSS test"
            result["test_payload"] = payload
            if "body_sample" in result:
                result["signature_hints"] = {
                    "payload_reflected": payload in result["body_sample"],
                    "escaped_payload_reflected": "&lt;script&gt;" in result["body_sample"].lower(),
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
        login_url = self.target + "/vulnapp/login.jsp"

        admin_keywords = [
            "admin page",
            "system config",
            "user list",
            "backup download",
            "관리자",
        ]

        def add_admin_hints(result):
            if "body_sample" in result:
                body = result["body_sample"].lower()
                result["signature_hints"] = {
                    "contains_admin_keywords": any(keyword in body for keyword in admin_keywords),
                    "contains_login_keyword": "login" in body or "로그인" in body,
                    "redirect_to_login": result.get("status_code") in [301, 302, 303, 307, 308] and "login" in result.get("redirect_location", "").lower(),
                }
            return result

        # 1) 다른 진단 과정에서 생성된 쿠키가 섞이지 않도록 비로그인 전용 세션으로 요청한다.
        anonymous_session = requests.Session()
        anonymous_session.headers.update(HEADERS)

        try:
            res = anonymous_session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
            anonymous_result = self.response_to_dict(res, body_limit=1200)
            anonymous_result["redirect_location"] = res.headers.get("Location", "")
        except requests.RequestException as e:
            anonymous_result = {"url": url, "error": str(e)}

        anonymous_result = add_admin_hints(anonymous_result)

        # 2) 수동진단 기준 보완: 일반 사용자 로그인 후 관리자 페이지 접근 가능 여부도 수집한다.
        normal_user_session = requests.Session()
        normal_user_session.headers.update(HEADERS)
        normal_user_result = {"url": url, "note": "normal user login probe not executed"}
        login_result = {"url": login_url, "note": "normal user login probe not executed"}

        try:
            login_res = normal_user_session.post(
                login_url,
                data={"id": NORMAL_USER_ID, "pw": NORMAL_USER_PW},
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
            login_result = self.response_to_dict(login_res, body_limit=600)
            login_result["redirect_location"] = login_res.headers.get("Location", "")
            login_result["test_account"] = NORMAL_USER_ID

            admin_res = normal_user_session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
            normal_user_result = self.response_to_dict(admin_res, body_limit=1200)
            normal_user_result["redirect_location"] = admin_res.headers.get("Location", "")
            normal_user_result["test_account"] = NORMAL_USER_ID
            normal_user_result = add_admin_hints(normal_user_result)
        except requests.RequestException as e:
            normal_user_result = {"url": url, "test_account": NORMAL_USER_ID, "error": str(e)}

        return {
            "anonymous_request": anonymous_result,
            "normal_user_login_request": login_result,
            "normal_user_request": normal_user_result,
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
        for idx in range(10):
            res = self.safe_request("POST", url, data={"id": "admin", "pw": f"wrong{idx}"})
            if isinstance(res, dict):
                attempts.append(res)
                continue
            attempts.append({"url": res.url, "status_code": res.status_code, "body_sample": res.text[:300]})
            if res.status_code in [423, 429, 403]:
                blocked = True
        return {"url": url, "attempt_count": len(attempts), "blocked": blocked, "attempts": attempts}

    def collect_account_lockout(self):
        url = self.target + "/vulnapp/login.jsp"
        attempts = []
        blocked = False
        for idx in range(10):
            res = self.safe_request("POST", url, data={"id": "admin", "pw": f"wrong{idx}"})
            if isinstance(res, dict):
                attempts.append(res)
                continue
            body = res.text[:300]
            attempts.append({"url": res.url, "status_code": res.status_code, "body_sample": body})
            if res.status_code in [423, 429, 403] or any(k in body.lower() for k in ["locked", "계정", "잠금", "too many"]):
                blocked = True
        return {"url": url, "attempt_count": len(attempts), "blocked": blocked, "attempts": attempts}

    def collect_debug_true(self):
        urls = [
            self.target + "/vulnapp/debug.jsp",
            self.target + "/vulnapp/debug.jsp?debug=true",
        ]
        results = []
        for url in urls:
            res = self.safe_request("GET", url)
            result = self.response_to_dict(res, body_limit=1500)
            if "body_sample" in result:
                body = result["body_sample"].lower()
                result["signature_hints"] = {
                    "contains_debug_keywords": any(
                        keyword in body
                        for keyword in ["debug", "db_user", "db_password", "api_key", "internal_ip", "env", "classpath", "config", "stacktrace"]
                    )
                }
            results.append(result)
        return results

    def collect_optional_endpoint_status(self):
        """
        GPT가 존재하지 않는 기능을 임의로 만들지 않게 하기 위해
        대표적인 추가 취약점 엔드포인트의 존재 여부만 수집한다.
        """
        endpoints = [
            "/vulnapp/upload.jsp",
            "/vulnapp/upload_process.jsp",
            "/vulnapp/search.jsp",
            "/vulnapp/profile.jsp?user_idx=1",
            "/vulnapp/ping.jsp",
            "/vulnapp/register.jsp",
            "/vulnapp/fetch.jsp",
            "/vulnapp/internal/secret.jsp"
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
9. upload.jsp, upload_process.jsp, profile.jsp, ping.jsp, register.jsp, fetch.jsp, internal/secret.jsp 등 존재가 확인되지 않은 엔드포인트 취약점은 생성하지 마라.
10. evidence에는 어떤 응답, 상태코드, 헤더, 본문 샘플, 테스트 반응이 근거인지 구체적으로 작성하라.
11. 아래 권장 check_id 목록의 모든 항목을 assessments에 반드시 1개씩 포함하라.
12. severity는 critical, high, medium, low, pass, n/a, pending 중 하나로 작성하라.
13. 수동진단표 기준 위험도와 맞추기 위해 다음 항목은 취약으로 판단될 경우 지정된 severity를 우선 사용하라: WEB-A01-001=medium, WEB-A02-004=medium, WEB-A04-001=medium, WEB-A05-002=medium.
14. result가 양호이면 severity는 pass로 작성하라.
15. result가 N/A이면 severity는 n/a로 작성하라.
16. 사이트 오류나 기능 미구현 때문에 취약/양호/N/A를 확정할 수 없으면 severity는 pending으로 작성하라.
17. url에는 해당 취약점이 발생하거나 점검된 대표 경로를 넣어라. 예: /vulnapp/login.jsp
18. confidence는 High, Medium, Low 중 하나로 작성하라.
19. 출력은 반드시 JSON 형식이어야 한다.

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
                                            "enum": ["critical", "high", "medium", "low", "pass", "n/a", "pending"]
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
11. upload.jsp, upload_process.jsp, profile.jsp, ping.jsp, register.jsp, fetch.jsp, internal/secret.jsp 등 존재가 확인되지 않은 엔드포인트 취약점은 생성하지 마라.
12. 잘 방어된 항목은 severity를 pass로 작성하라. 사이트 오류나 기능 미구현으로 판단할 수 없는 항목은 pending으로 작성하라.
13. 해당 기술/기능이 실제로 없어 진단 대상이 아니면 severity를 n/a로 작성하라. 단, 기능이 구현될 예정인데 404/500 등 사이트 오류로 판단하지 못하는 경우는 pending으로 작성하라.
14. 취약점이 확인된 항목만 critical, high, medium, low 중 하나를 사용하라.
15. evidence에는 pass, n/a, pending 판단의 이유도 분명히 적어라.
16. url에는 해당 취약점이 발생하거나 점검된 대표 경로를 넣어라. 예: /vulnapp/login.jsp
17. results의 id는 RES-0001부터 순서대로 작성하라.
18. summary.total은 results 개수와 같아야 한다.
19. summary.severity는 results의 severity 개수를 집계한 값이어야 한다.
20. 출력은 반드시 JSON 형식이어야 한다.
21. 공격 절차를 자세히 설명하지 말고, 방어적 진단 결과와 조치 중심으로 작성하라.
22. SQL Injection(WEB-A05-001)에서 signature_based_report 안의 sqlmap_summary, current_db, databases, dbms_banner, current_user 정보가 있으면 evidence에 자연스러운 문장으로 반드시 반영하라. WEB-A01-001은 anonymous_request와 normal_user_request를 모두 보고, 비로그인 접근은 차단되더라도 일반 사용자 세션으로 관리자 페이지가 200 응답이면 medium 취약으로 판단하라. WEB-A05-002는 실제 파라미터 keyword를 우선 사용하고, Reflected XSS는 이번 프로젝트 기준 medium으로 판단하라. WEB-A02-004 debug 정보 노출과 WEB-A04-001 HTTPS 미적용도 이번 프로젝트 기준 medium으로 판단하라. WEB-A10-002는 임의 파일 읽기가 아니라 SSRF로 판단하라. WEB-A08-001에서 JSP 파일 업로드 후 웹 경로에서 JSP 실행이 확인되면 서버 측 코드 실행 가능성이므로 critical로 판단하라.

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
                                            "n/a": {"type": "integer"},
                                            "pending": {"type": "integer"}
                                        },
                                        "required": [
                                            "critical",
                                            "high",
                                            "medium",
                                            "low",
                                            "pass",
                                            "n/a",
                                            "pending"
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
                                                "n/a",
                                                "pending"
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
    print(f"Critical: {severity.get('critical', 0)}")
    print(f"High: {severity['high']}")
    print(f"Medium: {severity['medium']}")
    print(f"Low: {severity['low']}")
    print(f"Pass: {severity['pass']}")
    print(f"N/A: {severity['n/a']}")
    print(f"Pending: {severity.get('pending', 0)}")
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
            run_sqlmap=rule_sqlmap,
            tomcat_port=tomcat_port
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
