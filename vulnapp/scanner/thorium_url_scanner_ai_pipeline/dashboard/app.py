import os
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

API_URL = os.getenv("API_URL", "http://api:8000")

st.set_page_config(page_title="URL 취약점 진단 대시보드", layout="wide")
st_autorefresh(interval=5000, key="refresh")

st.title("Thorium-inspired URL 취약점 자동 진단 대시보드")

st.warning("본인 소유 또는 허가받은 URL에만 사용한다.")

with st.sidebar:
    st.header("검색/필터")
    q = st.text_input("검색어", "")
    risk = st.selectbox("위험도", ["", "Critical", "High", "Medium", "Low", "Info"])
    finding_type = st.text_input("진단 항목", "")
    st.caption("5초마다 자동 새로고침")


def get_json(path, params=None):
    try:
        r = requests.get(f"{API_URL}{path}", params=params, timeout=20)
        return r.json()
    except Exception as e:
        st.error(f"API 연결 실패: {e}")
        return None


def post_json(path, body):
    try:
        r = requests.post(f"{API_URL}{path}", json=body, timeout=120)
        return r.json()
    except Exception as e:
        st.error(f"API 요청 실패: {e}")
        return None


st.subheader("URL 직접 진단")
target_url = st.text_input("대상 URL", placeholder="http://example.com/page.php?id=1")
enable_ai = st.checkbox("GPT 분석 활성화", value=True)

if st.button("진단 시작"):
    if not target_url:
        st.error("URL을 입력해야 한다.")
    else:
        with st.spinner("진단 중..."):
            result = post_json("/scan", {"target_url": target_url, "enable_ai": enable_ai})
            st.success("진단 완료")
            st.json(result)

stats = get_json("/stats") or {}
params = {"limit": 500}
if q:
    params["q"] = q
if risk:
    params["risk"] = risk
if finding_type:
    params["finding_type"] = finding_type

findings = get_json("/findings", params=params) or []
df = pd.DataFrame(findings)

c1, c2, c3, c4 = st.columns(4)
risk_map = {x["risk"]: x["c"] for x in stats.get("by_risk", [])}

c1.metric("총 진단 결과", stats.get("total", 0))
c2.metric("Critical", risk_map.get("Critical", 0))
c3.metric("High", risk_map.get("High", 0))
c4.metric("Medium/Low", risk_map.get("Medium", 0) + risk_map.get("Low", 0))

left, right = st.columns(2)

with left:
    st.subheader("진단 항목별 결과")
    by_type = pd.DataFrame(stats.get("by_type", []))
    if not by_type.empty:
        fig = px.bar(by_type, x="finding_type", y="c", text="c")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("진단 결과가 아직 없다.")

with right:
    st.subheader("위험도 분포")
    by_risk = pd.DataFrame(stats.get("by_risk", []))
    if not by_risk.empty:
        fig = px.pie(by_risk, names="risk", values="c")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("진단 결과가 아직 없다.")

st.subheader("최근 스캔")
recent_scans = pd.DataFrame(stats.get("recent_scans", []))
if not recent_scans.empty:
    st.dataframe(recent_scans, use_container_width=True)

st.subheader("진단 상세 결과")
if not df.empty:
    show_cols = [
        "created_at", "target_url", "finding_type", "risk", "url",
        "evidence", "ai_summary", "recommendation"
    ]
    show_cols = [c for c in show_cols if c in df.columns]
    st.dataframe(df[show_cols], use_container_width=True, height=450)
else:
    st.info("아직 데이터가 없다.")

st.subheader("CVE 키워드 조회")
keyword = st.text_input("예: Apache 2.4.49, OpenSSL, PHP")
if st.button("CVE 조회") and keyword:
    cves = get_json("/cve", params={"keyword": keyword})
    st.json(cves)
