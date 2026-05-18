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

# --- 사이드바 설정 ---
st.sidebar.title("🛠️ 진단 설정")
input_method = st.sidebar.radio(
    "데이터 입력 방식 선택",
    ("URL 기반 실시간 진단", "엑셀 파일 직접 업로드")
)

# 💡 타이틀 동적 변경 로직
st.caption("🚀 웹 취약점 진단 비교 대시보드")
st.title(f"🛡️ {input_method}")

# manual_df = None
# auto_df = None
# current_target = "-"

# URL 진단용과 파일 업로드용 세션을 각각 분리하여 초기화합니다.
if 'url_data_loaded' not in st.session_state:
    st.session_state['url_data_loaded'] = False
    st.session_state['url_manual_df'] = None
    st.session_state['url_auto_df'] = None
    st.session_state['url_current_target'] = "-"

if 'file_data_loaded' not in st.session_state:
    st.session_state['file_data_loaded'] = False
    st.session_state['file_manual_df'] = None
    st.session_state['file_auto_df'] = None
    st.session_state['file_current_target'] = "-"

# --- 메인 영역: 입력부 ---
if input_method == "URL 기반 실시간 진단":
    target_url = st.text_input(
        "진단 대상 웹 애플리케이션 URL",
        placeholder="예: http://15.164.60.79"
    )
    current_target = target_url
    scan_button = st.button("실시간 진단 시작")

    if scan_button:
        if not target_url:
            st.warning("진단 대상 URL을 입력해주세요.")
        else:
            try:
                with st.spinner("백엔드 서버에서 진단을 수행 중입니다..."):
                    # 실제 API 호출
                    auto_excel = request_scan_result(target_url)
                    
                    # 앞에 url_을 붙여 URL 진단 전용 세션 변수에 담아줍니다.
                    st.session_state['url_manual_df'] = pd.DataFrame() 
                    st.session_state['url_auto_df'] = load_auto_excel(auto_excel)
                    st.session_state['url_current_target'] = target_url
                    st.session_state['url_data_loaded'] = True
                    
                    # 수동 진단 데이터는 완전히 비어있는(Empty) 상태로 넘겨서 에러 방지
                    # manual_df = pd.DataFrame() 
                    # auto_df = load_auto_excel(auto_excel)
                            
                    # UI 처리 (다운로드 버튼 1개 표시)
                    st.success("✅ 실시간 진단 및 데이터 수신이 완료되었습니다!")
                            
                    with open(auto_excel, "rb") as f:
                        st.download_button(
                            label="📥 자동진단 결과 다운로드 (.xlsx)",
                            data=f,
                            file_name="자동진단_결과.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            use_container_width=True
                        )
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
                # 앞에 file_을 붙여 업로드 전용 세션 변수에 담아줍니다.
                st.session_state['file_manual_df'] = load_manual_excel(manual_file)
                st.session_state['file_auto_df'] = load_auto_excel(auto_file)
                st.session_state['file_current_target'] = f"수동: {manual_file.name} / 자동: {auto_file.name}"
                st.session_state['file_data_loaded'] = True
                
                # manual_df = load_manual_excel(manual_file)
                # auto_df = load_auto_excel(auto_file)
                
                # 파일명을 가져와서 진단 대상(current_target)으로 설정
                # current_target = f"수동 진단 데이터: {manual_file.name} / 자동 진단 데이터: {auto_file.name}"
                
            except Exception as e:
                st.error(f"파일 로드 중 오류가 발생했습니다: {e}")
        else:
            st.warning("두 개의 파일을 모두 업로드해주세요.")

# --- 메인 영역: 결과 출력부 ---
# 현재 라디오 버튼 상태(input_method)를 판별하여 알맞은 모드의 데이터만 렌더링합니다.
if input_method == "URL 기반 실시간 진단":
    if st.session_state['url_data_loaded']:
        render_dashboard(
            st.session_state['url_manual_df'], 
            st.session_state['url_auto_df'], 
            target_url=st.session_state['url_current_target'], 
            is_realtime=True
        )
    else:
        st.divider()
        st.write("진단 대상 URL을 입력한 후 '실시간 진단 시작' 버튼을 눌러주세요.")
else:  # 엑셀 파일 직접 업로드 방식
    if st.session_state['file_data_loaded']:
        render_dashboard(
            st.session_state['file_manual_df'], 
            st.session_state['file_auto_df'], 
            target_url=st.session_state['file_current_target'], 
            is_realtime=False
        )
    else:
        st.divider()
        st.write("수동 진단 및 자동 진단 엑셀 파일을 업로드한 후 '업로드 데이터 분석 시작' 버튼을 눌러주세요.")

# if manual_df is not None and auto_df is not None:
#     # 현재 선택된 모드가 실시간 진단인지 여부를 확인
#     is_realtime_mode = (input_method == "URL 기반 실시간 진단")
    
#     # 렌더링 함수에 is_realtime 플래그를 추가로 넘겨줌
#     render_dashboard(manual_df, auto_df, target_url=current_target, is_realtime=is_realtime_mode)
# else:
#     st.divider()
#     st.write("위에서 데이터를 입력하거나 파일을 업로드한 후 버튼을 눌러주세요.")