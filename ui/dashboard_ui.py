import streamlit as st
import pandas as pd
import plotly.express as px
import datetime

from config import SEVERITY_COLORS, CARD_COLORS, DISPLAY_COLUMNS
from utils.metrics import calculate_metrics

from config import SEVERITY_COLORS, CARD_COLORS
from utils.metrics import calculate_metrics

def render_dashboard(manual_df: pd.DataFrame, auto_df: pd.DataFrame, target_url: str = "-", is_realtime: bool = False):
    """전체 대시보드를 렌더링합니다."""
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    standard_columns = [
        "source", "target", "detected_at", "id", 
        "vuln_code", "owasp", "vuln_name", "severity", 
        "evidence", "recommendation"
    ]

    def unify_dataframe(df, source_type):
        if df is None or df.empty:
            return pd.DataFrame(columns=standard_columns)
        
        temp_df = df.copy()
        for col in standard_columns:
            if col not in temp_df.columns:
                temp_df[col] = None
                
        temp_df["target"] = temp_df["target"].fillna(target_url)
        if target_url == "":
            temp_df["target"] = temp_df["target"].replace("", "Unknown Target")

        temp_df["detected_at"] = temp_df["detected_at"].replace("-", current_time)
        temp_df["detected_at"] = temp_df["detected_at"].fillna(current_time)
            
        return temp_df[standard_columns]

    manual_df_clean = unify_dataframe(manual_df, "manual")
    auto_df_clean = unify_dataframe(auto_df, "auto")

    # 1. 수동 진단 데이터 컬럼 중복 제거
    if not manual_df_clean.columns.is_unique:
    # 중복된 컬럼 중 첫 번째 컬럼만 남김
        manual_df_clean = manual_df_clean.loc[:, ~manual_df_clean.columns.duplicated()]

    # 2. 자동 진단 데이터 컬럼 중복 제거
    if not auto_df_clean.columns.is_unique:
    # 중복된 컬럼 중 첫 번째 컬럼만 남김
        auto_df_clean = auto_df_clean.loc[:, ~auto_df_clean.columns.duplicated()]

# 기존 코드 실행
    combined_df = pd.concat([manual_df_clean, auto_df_clean], ignore_index=True)

    
    
    if combined_df.empty:
        st.warning("분석할 데이터가 없습니다. 파일을 확인해 주세요.")
        return

    metrics = calculate_metrics(manual_df_clean, auto_df_clean)

    st.markdown(f"### 🎯 진단 대상: `{target_url}`")
    st.divider()

    # 아래처럼 이 함수에도 is_realtime을 꼭 괄호 안에 넣어주세요!
    render_metric_cards(metrics, is_realtime) 
    st.divider()
    # ... 기존 코드 ...
    
    # 그래프 렌더링 (is_realtime 전달)
    render_charts(manual_df_clean, auto_df_clean, combined_df, is_realtime)
    st.divider()
    
    # 테이블 렌더링 (is_realtime 전달)
    render_result_tables(manual_df_clean, auto_df_clean, is_realtime)


def render_target_section(target_url: str):
    st.subheader("진단 대상")

    st.info(f"대상 웹 애플리케이션: {target_url}")


def render_color_card(title, value, subtitle, color):
    st.markdown(
        f"""
        <div style="
            background-color: {color};
            padding: 22px 18px;
            border-radius: 16px;
            color: white;
            min-height: 125px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        ">
            <div style="font-size: 15px; font-weight: 600; opacity: 0.95;">
                {title}
            </div>
            <div style="font-size: 34px; font-weight: 800; margin-top: 8px;">
                {value}
            </div>
            <div style="font-size: 13px; margin-top: 6px; opacity: 0.9;">
                {subtitle}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_cards(metrics: dict, is_realtime: bool = False):
    st.subheader("핵심 요약 지표")

    if is_realtime:
        # [실시간 진단 모드] 7개 카드만 표시 (수동, 자동 제외)
        col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

        with col1:
            render_color_card("전체 탐지", f"{metrics['total_count']}개", "탐지된 취약점", CARD_COLORS["total"])
        with col2:
            render_color_card("Critical", f"{metrics['critical_count']}개", "즉시 조치 필요", CARD_COLORS["critical"])
        with col3:
            render_color_card("High", f"{metrics['high_count']}개", "높은 위험", CARD_COLORS["high"])
        with col4:
            render_color_card("Medium", f"{metrics['medium_count']}개", "주의 필요", CARD_COLORS["medium"])
        with col5:
            render_color_card("Low", f"{metrics['low_count']}개", "낮은 위험", CARD_COLORS["low"])
        with col6:
            render_color_card("Pass", f"{metrics['pass_count']}개", "양호 (안전)", CARD_COLORS["pass"])
        with col7:
            render_color_card("N/A", f"{metrics['na_count']}개", "해당 없음", CARD_COLORS["n/a"])

    else:
        # [엑셀 업로드 모드] 9개 카드 모두 표시 (기존 유지)
        col1, col2, col3, col4, col5, col6, col7, col8, col9 = st.columns(9)

        with col1:
            render_color_card("전체 탐지", f"{metrics['total_count']}개", "수동 + 자동", CARD_COLORS["total"])
        with col2:
            render_color_card("수동진단", f"{metrics['manual_count']}개", "수동 점검 결과", CARD_COLORS["manual"])
        with col3:
            render_color_card("자동진단", f"{metrics['auto_count']}개", "자동 점검 결과", CARD_COLORS["auto"])
        with col4:
            render_color_card("Critical", f"{metrics['critical_count']}개", "즉시 조치 필요", CARD_COLORS["critical"])
        with col5:
            render_color_card("High", f"{metrics['high_count']}개", "높은 위험", CARD_COLORS["high"])
        with col6:
            render_color_card("Medium", f"{metrics['medium_count']}개", "주의 필요", CARD_COLORS["medium"])
        with col7:
            render_color_card("Low", f"{metrics['low_count']}개", "낮은 위험", CARD_COLORS["low"])
        with col8:
            render_color_card("Pass", f"{metrics['pass_count']}개", "양호 (안전)", CARD_COLORS["pass"])
        with col9:
            render_color_card("N/A", f"{metrics['na_count']}개", "해당 없음", CARD_COLORS["n/a"])

    # 범례 그리는 함수에도 플래그 전달
    render_color_legend(is_realtime)

def render_color_legend(is_realtime: bool = False):
    st.markdown("#### 색상 기준")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown("⬛ **회색**: 전체 탐지 결과")
        if not is_realtime:
            # 엑셀 업로드 모드에서만 수동/자동 색상 표시
            st.markdown("🔵 **파랑**: 수동진단 결과")
            st.markdown("🟪 **보라색**: 자동진단 결과")

    with col2:
        st.markdown("🟥 **진한 빨강**: Critical")
        st.markdown("🔴 **빨강**: High")

    with col3:
        st.markdown("🟨 **노랑**: Medium")
        st.markdown("🟦 **하늘색**: Low")

    with col4:
        st.markdown("🟢 **초록**: Pass (양호)")
        st.markdown("⚪ **연한 회색**: N/A (해당없음)")
        st.markdown("🔘 **회색**: Info 또는 기타")


def render_charts(
    manual_df: pd.DataFrame,
    auto_df: pd.DataFrame,
    combined_df: pd.DataFrame,
    is_realtime: bool = False
):
    st.subheader("분석 그래프")

    if is_realtime:
        # [실시간 진단 모드] 수동진단 그래프를 없애고 도넛 그래프 2개만 나란히 표시
        col1, col2 = st.columns(2)
        with col1:
            render_severity_pie(combined_df)
        with col2:
            render_attack_type_pie(auto_df)
    else:
        # [엑셀 업로드 모드] 기존 3가지 그래프 표시
        col1, col2 = st.columns(2)
        with col1:
            render_source_count_bar(manual_df, auto_df)
        with col2:
            render_severity_pie(combined_df)
        render_source_severity_bar(combined_df)

def render_attack_type_pie(auto_df: pd.DataFrame):
    if "owasp" not in auto_df.columns:
        st.info("OWASP 공격 유형 데이터가 없습니다.")
        return
        
    # '-'나 결측치 제외
    valid_df = auto_df[auto_df["owasp"] != "-"]
    if valid_df.empty:
        st.info("탐지된 공격 유형(OWASP)이 없습니다.")
        return
        
    chart_df = valid_df["owasp"].value_counts().reset_index()
    chart_df.columns = ["owasp", "count"]
    total_count = chart_df["count"].sum()

    fig = px.pie(
        chart_df,
        names="owasp",
        values="count",
        hole=0.55,
        title="공격 유형 분포 (OWASP Top 10)",
    )
    
    # 도넛 가운데에 전체 개수 표시 (보내주신 이미지 스타일 적용)
    fig.update_layout(
        annotations=[dict(text=f"<b>{total_count}</b><br>전체", x=0.5, y=0.5, font_size=24, showarrow=False)],
        showlegend=True
    )
    fig.update_traces(textinfo='percent', textposition='inside')

    st.plotly_chart(fig, use_container_width=True, key="chart_attack_type")


def render_source_count_bar(manual_df: pd.DataFrame, auto_df: pd.DataFrame):
    chart_df = pd.DataFrame(
        {
            "진단 방식": ["수동진단", "자동진단"],
            "탐지 건수": [len(manual_df), len(auto_df)],
        }
    )

    fig = px.bar(
        chart_df,
        x="진단 방식",
        y="탐지 건수",
        text="탐지 건수",
        title="진단 방식별 탐지 건수",
        color="진단 방식",
        color_discrete_map={
            "수동진단": CARD_COLORS["manual"],
            "자동진단": CARD_COLORS["auto"],
        },
    )

    fig.update_traces(textposition="outside")
    fig.update_layout(
        xaxis_title="",
        yaxis_title="탐지 건수",
        showlegend=False,
    )
    fig.update_traces(width=0.3)

    st.plotly_chart(fig, use_container_width=True, key="chart_source_count")


def render_severity_pie(combined_df: pd.DataFrame):
    chart_df = combined_df["severity"].value_counts().reset_index()
    chart_df.columns = ["severity", "count"]

    # 2. 위험도가 'n/a'인 항목은 그래프 데이터에서 제외
    chart_df = chart_df[chart_df["severity"] != "n/a"]

    fig = px.pie(
        chart_df,
        names="severity",
        values="count",
        hole=0.45,
        title="위험도 분포",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
    )

    fig.update_traces(textinfo='percent', textposition='inside')

    st.plotly_chart(fig, use_container_width=True, key="chart_severity_pie")


def render_source_severity_bar(combined_df: pd.DataFrame):
    st.subheader("진단 방식별 위험도 분포")

    if "source" not in combined_df.columns:
        st.info("진단 방식 데이터가 없습니다.")
        return

    # 1. 그래프에 표시할 4가지 핵심 위험도만 필터링 (대소문자 일치)
    target_severities = ["critical", "high", "medium", "low"]
    filtered_df = combined_df[combined_df["severity"].isin(target_severities)]

    # 2. 위험도(severity)와 진단방식(source)을 기준으로 개수 집계
    chart_df = (
        filtered_df.groupby(["severity", "source"])
        .size()
        .reset_index(name="count")
    )

    # 3. 막대 그래프 생성 (X축: 위험도, 막대색상: 진단방식)
    fig = px.bar(
        chart_df,
        x="severity",      # X축을 위험도로 변경
        y="count",
        color="source",    # 색상 구분을 진단 방식으로 변경
        text="count",
        title="Severity 분포 비교",
        color_discrete_map={
            "수동진단": CARD_COLORS["manual"],  # 파란색 계열
            "자동진단": CARD_COLORS["auto"]     # 보라색/초록색 계열
        },
        category_orders={"severity": target_severities} # X축 순서 고정 (Critical -> High -> Medium -> Low)
    )

    fig.update_traces(textposition="outside")
    fig.update_layout(
        xaxis_title="위험도",
        yaxis_title="개수",
        barmode="group",        # 막대를 나란히 배치
        legend_title_text=""    # 범례 타이틀 숨기기 (더 깔끔하게)
    )

    st.plotly_chart(fig, use_container_width=True, key="chart_source_severity")

def style_severity(val):
    val_lower = str(val).lower()
    if "critical" in val_lower or "치명" in val_lower:
        color, text = "#DC2626", "white"
    elif "high" in val_lower or "상" in val_lower:
        color, text = "#EA580C", "white"
    elif "medium" in val_lower or "med" in val_lower or "중" in val_lower:
        color, text = "#FACC15", "black"
    elif "low" in val_lower or "하" in val_lower:
        color, text = "#16A34A", "white"
    else:
        return ""
    return f"background-color: {color}; color: {text}; font-weight: bold; text-align: center;"

def render_result_tables(manual_df: pd.DataFrame, auto_df: pd.DataFrame, is_realtime: bool = False):
    st.subheader("상세 진단 결과")

    if is_realtime:
        # [실시간 진단 모드] 수동 탭 없애고 자동진단 결과만 바로 출력
        render_single_result_table(auto_df, "자동진단 결과")
    else:
        # [엑셀 업로드 모드] 기존 탭 2개 유지
        tab1, tab2 = st.tabs(["수동진단 결과", "자동진단 결과"])
        with tab1:
            render_single_result_table(manual_df, "수동진단")
        with tab2:
            render_single_result_table(auto_df, "자동진단")


def render_single_result_table(df: pd.DataFrame, title: str):
    st.write(f"### {title}")

    filtered_df = render_filters(df, key_prefix=title)

    display_columns = [col for col in DISPLAY_COLUMNS if col in filtered_df.columns]

    st.dataframe(
    filtered_df[display_columns].style.map(style_severity, subset=["severity"]), # 🔄 여기에만 .style.map을 붙였습니다!
    use_container_width=True,
    hide_index=True,
    )

    render_detail_section(filtered_df, title)


def render_filters(df: pd.DataFrame, key_prefix: str) -> pd.DataFrame:
    col1, col2 = st.columns(2)

    severity_options = ["전체"] + sorted(df["severity"].dropna().unique().tolist())

    if "vuln_name" in df.columns:
        vuln_options = ["전체"] + sorted(df["vuln_name"].dropna().unique().tolist())
    else:
        vuln_options = ["전체"]

    with col1:
        selected_severity = st.selectbox(
            "위험도 필터",
            severity_options,
            key=f"{key_prefix}_severity_filter",
        )

    with col2:
        selected_vuln = st.selectbox(
            "취약점명 필터",
            vuln_options,
            key=f"{key_prefix}_vuln_filter",
        )

    filtered_df = df.copy()

    if selected_severity != "전체":
        filtered_df = filtered_df[filtered_df["severity"] == selected_severity]

    if selected_vuln != "전체" and "vuln_name" in filtered_df.columns:
        filtered_df = filtered_df[filtered_df["vuln_name"] == selected_vuln]

    return filtered_df


def render_detail_section(filtered_df: pd.DataFrame, title: str):
    st.write(f"### {title} 항목별 상세 보기")

    if filtered_df.empty:
        st.info("선택된 조건에 해당하는 진단 결과가 없습니다.")
        return

    for _, row in filtered_df.iterrows():
        vuln_name = row.get("vuln_name", "-")
        severity = row.get("severity", "-")
        detected_at = row.get("detected_at", "-")

        expander_title = f"{severity.upper()} | {vuln_name}"

        if detected_at != "-":
            expander_title = f"{detected_at} | {expander_title}"

        with st.expander(expander_title):
            col1, col2 = st.columns(2)

            with col1:
                st.write("#### 기본 정보")
                st.write(f"**진단 방식:** {row.get('source', title)}")
                st.write(f"**진단 대상:** {row.get('target', '-')}")
                st.write(f"**탐지 시간:** {row.get('detected_at', '-')}")
                st.write(f"**위험도:** {row.get('severity', '-')}")
                st.write(f"**취약점명:** {row.get('vuln_name', '-')}")

                if "vuln_code" in row:
                    st.write(f"**항목 코드:** {row.get('vuln_code', '-')}")

                if "owasp" in row:
                    st.write(f"**OWASP:** {row.get('owasp', '-')}")

            with col2:
                st.write("#### 진단 근거")
                st.info(row.get("evidence", "-"))

            st.markdown("---")

            st.write("#### 대응 방안")
            st.success(row.get("recommendation", "-"))