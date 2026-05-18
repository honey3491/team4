import pandas as pd

# 1. [추가] 자주 쓰이는 다양한 컬럼명들을 표준 이름으로 매핑하는 사전
COLUMN_ALIASES = {
    # target 관련
    "대상": "target", "url": "target", "ip": "target",
    # id 관련
    "연번": "id", "no": "id", "번호": "id",
    # vuln_code 관련
    "주정통_항목코드": "vuln_code", "항목코드": "vuln_code", "코드": "vuln_code", "check_id": "vuln_code", "항목번호": "vuln_code",
    # vuln_name 관련
    "점검 항목": "vuln_name", "name":"vuln_name", "점검항목": "vuln_name", "취약점명": "vuln_name", "항목명": "vuln_name", "진단항목": "vuln_name",
    # severity 관련
    "위험도": "severity", "등급": "severity", "level": "severity",
    # evidence 관련
    "증적": "evidence", "발견내용": "evidence", "증적자료": "evidence", "세부내용": "evidence", "진단결과": "evidence",
    # recommendation 관련
    "대응방안": "recommendation", "조치방안": "recommendation", "해결방안": "recommendation", "가이드": "recommendation",
    # auto excel 전용
    "generated_at": "detected_at", "진단일자": "detected_at", "날짜": "detected_at", "생성일": "detected_at"
}

def rename_columns_flexibly(df: pd.DataFrame) -> pd.DataFrame:
    """컬럼명의 공백을 제거하고, ALIAS 사전을 기반으로 표준 이름으로 변경합니다."""
    # 소문자로 변환하고 양쪽 공백을 제거하여 비교하기 쉽게 만듦
    current_columns = {col: str(col).strip().lower() for col in df.columns}
    
    rename_dict = {}
    for original_col, clean_col in current_columns.items():
        # 사전에서 매칭되는 값이 있으면 그 값으로, 없으면 원래 이름(공백제거) 유지
        standard_name = COLUMN_ALIASES.get(clean_col, clean_col)
        rename_dict[original_col] = standard_name
        
    return df.rename(columns=rename_dict)


def load_manual_excel(file_or_path) -> pd.DataFrame:
    df = pd.read_excel(file_or_path)
    
    # 유연한 컬럼명 변경 로직 적용
    df = rename_columns_flexibly(df)

    # 대시보드에서 사용하는 표준 컬럼 목록
    standard_columns = [
        "source", "target", "detected_at", "id", 
        "vuln_code", "vuln_name", "severity", "evidence", "recommendation"
    ]

    # 강제 오류(raise ValueError) 발생 로직을 삭제하고, 없는 컬럼은 "-"로 채움
    for col in standard_columns:
        if col not in df.columns:
            df[col] = "-"

    df["source"] = "수동진단"
    # 수동진단에 시간이 없으면 "-"로 통일 (dashboard_ui.py에서 현재 시간으로 덮어씀)
    if "detected_at" not in df.columns or df["detected_at"].isnull().all():
        df["detected_at"] = "-"

    df["severity"] = normalize_severity(df["severity"])

    return df[standard_columns].fillna("-")


def load_auto_excel(file_or_path) -> pd.DataFrame:
    df = read_auto_findings_sheet(file_or_path)
    
    # 유연한 컬럼명 변경 로직 적용
    df = rename_columns_flexibly(df)

    standard_columns = [
        "source", "target", "detected_at", "id", 
        "vuln_code", "owasp", "vuln_name", "severity", "evidence", "recommendation"
    ]

    # 강제 오류 발생 로직 삭제, 없는 컬럼 생성
    for col in standard_columns:
        if col not in df.columns:
            df[col] = "-"

    df["source"] = "자동진단"
    df["severity"] = normalize_severity(df["severity"])

    return df[standard_columns].fillna("-")

# (이하 read_auto_findings_sheet, normalize_severity 함수는 기존에 수정한 그대로 유지)


def read_auto_findings_sheet(file_or_path) -> pd.DataFrame:
    """
    자동진단 엑셀에서 findings 시트를 우선적으로 읽습니다.
    findings 시트가 없으면 첫 번째 시트를 읽습니다.
    """

    excel_file = pd.ExcelFile(file_or_path)

    if "findings" in excel_file.sheet_names:
        return pd.read_excel(file_or_path, sheet_name="findings")

    return pd.read_excel(file_or_path, sheet_name=excel_file.sheet_names[0])


def normalize_severity(series: pd.Series) -> pd.Series:
    """
    위험도 값을 표준 값으로 통일합니다.
    """
    # [추가된 핵심 방어 로직] 
    # 문자로 변환하기 전에, 아예 비어있는 결측치(NaN, None 등)를 먼저 "n/a"로 꽉 채웁니다.
    series = series.fillna("n/a")

    return (
        series.astype(str)
        .str.strip()
        .str.lower()
        .replace(
            {
                "critical": "critical",
                "crit": "critical",

                "high": "high",
                "상": "high",
                "높음": "high",

                "medium": "medium",
                "med": "medium",
                "중": "medium",
                "보통": "medium",

                "low": "low",
                "하": "low",
                "낮음": "low",

                "info": "info",
                "정보": "info",

                "pass": "pass",
                "passed": "pass",
                "양호": "pass",
                "정상": "pass",
                "safe": "pass",

                "n/a": "n/a",
                "na": "n/a",
                "n.a": "n/a",
                "해당없음": "n/a",
                "해당 없음": "n/a",
                "판단불가": "n/a",
                "-": "n/a",
                
                # [추가된 문자열 방어 로직] 최신 판다스 버전 및 특수 문자열 완벽 대응
                "nan": "n/a",
                "<na>": "n/a",
                "none": "n/a",
                "null": "n/a",
                "": "n/a",
            }
        )
    )