import streamlit as st
import pandas as pd
from config import APP_TITLE
from api.client import request_scan_result
from utils.loader import load_manual_excel, load_auto_excel
from ui.dashboard_ui import render_dashboard

st.set_page_config(
    page_title=APP_TITLE,
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ 웹 취약점 진단 비교 대시보드")

# --- 사이드바 설정 ---
st.sidebar.title("🛠️ 진단 설정")
input_method = st.sidebar.radio(
    "데이터 입력 방식 선택",
    ("URL 기반 실시간 진단", "엑셀 파일 직접 업로드")
)

# ⭐ [새로고침 되어도 데이터를 기억하도록 세션 상태 공간을 생성합니다]
if "manual_df" not in st.session_state:
    st.session_state.manual_df = None
if "auto_df" not in st.session_state:
    st.session_state.auto_df = None
if "current_target" not in st.session_state:
    st.session_state.current_target = "-"
if "auto_excel_path" not in st.session_state:
    st.session_state.auto_excel_path = None

# ⭐ [기존 코드들과의 호환성을 위해 세션 값을 일반 변수에 연결해 줍니다]
manual_df = st.session_state.manual_df
auto_df = st.session_state.auto_df
current_target = st.session_state.current_target

# --- 메인 영역: 입력부 ---
if input_method == "URL 기반 실시간 진단":
    target_url = st.text_input(
        "진단 대상 웹 애플리케이션 URL",
        placeholder="예: http://15.164.60.79"
    )
    current_target = target_url
    scan_button = st.button("실시간 진단 시작")

    if scan_button:
        # 🟢 1. use_mock 검사를 빼고 오직 URL 입력 여부만 검사하도록 바꿉니다.
        if not target_url:
            st.warning("진단 대상 URL을 입력해주세요.")
        else:
            try:
                with st.spinner("백엔드 서버에서 진단을 수행 중입니다..."):
                    auto_excel = request_scan_result(target_url)

                    # ⭐ [일반 변수가 아니라 세션 상태에 데이터를 박아 넣습니다]
                    st.session_state.manual_df = pd.DataFrame() 
                    st.session_state.auto_df = load_auto_excel(auto_excel)
                    st.session_state.current_target = target_url
                    st.session_state.auto_excel_path = auto_excel

                    # ⭐ [새로고침을 한 번 발생시켜 위 세션 데이터들을 앱에 완전히 고정시킵니다]
                    st.rerun()

            except Exception as e:
                st.error(f"진단 중 오류가 발생했습니다: {e}")

else:  # 엑셀 파일 직접 업로드 방식
    st.info("수동 진단과 자동 진단 결과 엑셀 파일을 업로드하세요.")
    col1, col2 = st.columns(2)
    
    with col1:
        manual_file = st.file_uploader("수동 진단 결과 업로드 (.xlsx)", type=["xlsx"])
    with col2:
        auto_file = st.file_uploader("자동 진단 결과 업로드 (.xlsx)", type=["xlsx"])
    
    
    if st.button("업로드 데이터 분석 시작"):
        if manual_file and auto_file:
            try:
                manual_df = load_manual_excel(manual_file)
                auto_df = load_auto_excel(auto_file)
                
                # [추가된 코드] 파일명을 가져와서 진단 대상(current_target)으로 설정합니다.
                current_target = f"수동 진단 데이터: {manual_file.name} / 자동 진단 데이터: {auto_file.name}"
                
            except Exception as e:
                st.error(f"파일 로드 중 오류가 발생했습니다: {e}")
        else:
            st.warning("두 개의 파일을 모두 업로드해주세요.")

# --- 메인 영역: 결과 출력부 ---
# --- 메인 영역: 결과 출력부 ---
if manual_df is not None and auto_df is not None:
    # 현재 선택된 모드가 실시간 진단인지 여부를 확인
    is_realtime_mode = (input_method == "URL 기반 실시간 진단")
    
    # ==============================================================================
    # [새로 추가되는 코드: 총 12줄] 
    #  진단 완료 후 새로고침이 되더라도 다운로드 버튼이 대시보드 위에 상시 살아있게 만듭니다!
    # ==============================================================================
    if is_realtime_mode and "auto_excel_path" in st.session_state and st.session_state.auto_excel_path:
        with open(st.session_state.auto_excel_path, "rb") as f:
            st.download_button(
                label="📥 자동진단 결과 다운로드 (.xlsx)",
                data=f,
                file_name="자동진단_결과.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )
    # ==============================================================================
    
    # 렌더링 함수에 is_realtime 플래그를 추가로 넘겨줌
    render_dashboard(manual_df, auto_df, target_url=current_target, is_realtime=is_realtime_mode)
    
else:
    st.divider()
    st.write("위에서 데이터를 입력하거나 파일을 업로드한 후 버튼을 눌러주세요.")