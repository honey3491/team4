APP_TITLE = "웹 애플리케이션 취약점 진단 대시보드"

MOCK_MANUAL_EXCEL_PATH = "data/수동진단.xlsx"
MOCK_AUTO_EXCEL_PATH = "data/자동진단.xlsx"

SEVERITY_COLORS = {
    "critical": "#7F1D1D",
    "high": "#DC2626",
    "medium": "#FACC15",
    "low": "#38BDF8",
    "info": "#9CA3AF",
    "pass": "#16A34A",   # 초록
    "n/a": "#D1D5DB",    # 연회색
}

CARD_COLORS = {
    "total": "#6B7280",
    "manual": "#2563EB",
    "auto": "#A855F7",
    "critical": "#7F1D1D",
    "high": "#DC2626",
    "medium": "#FACC15",
    "low": "#38BDF8",
    "pass": "#16A34A",
    "n/a": "#D1D5DB",
}

DISPLAY_COLUMNS = [
    "detected_at",          
    "severity",
    "vuln_name",
    "target",       
    "evidence",
    "recommendation",
]