import pandas as pd


def compare_scan_results(signature_df: pd.DataFrame, gpt_df: pd.DataFrame) -> pd.DataFrame:
    """
    Signature 기반 진단 결과와 GPT 기반 진단 결과를 check_id 기준으로 비교합니다.
    """

    merged_df = pd.merge(
        signature_df,
        gpt_df,
        on="check_id",
        how="outer",
        suffixes=("_signature", "_gpt"),
    )

    # 공통 정보 정리
    merged_df["owasp"] = merged_df["owasp_signature"].combine_first(
        merged_df["owasp_gpt"]
    )

    merged_df["name"] = merged_df["name_signature"].combine_first(
        merged_df["name_gpt"]
    )

    merged_df["severity"] = merged_df["severity_signature"].combine_first(
        merged_df["severity_gpt"]
    )

    merged_df["recommendation"] = merged_df["recommendation_signature"].combine_first(
        merged_df["recommendation_gpt"]
    )

    # 탐지 여부
    merged_df["signature_detected"] = merged_df["id_signature"].notna()
    merged_df["gpt_detected"] = merged_df["id_gpt"].notna()

    # 비교 결과
    merged_df["comparison"] = merged_df.apply(judge_detection_source, axis=1)

    # evidence 정리
    merged_df["signature_evidence"] = merged_df.get("evidence_signature", "-")
    merged_df["gpt_evidence"] = merged_df.get("evidence_gpt", "-")

    fill_values = {
        "owasp": "-",
        "name": "-",
        "severity": "N/A",
        "recommendation": "-",
        "signature_evidence": "-",
        "gpt_evidence": "-",
    }

    for column, value in fill_values.items():
        if column in merged_df.columns:
            merged_df[column] = merged_df[column].fillna(value)

    column_order = [
        "check_id",
        "owasp",
        "name",
        "severity",
        "signature_detected",
        "gpt_detected",
        "comparison",
        "signature_evidence",
        "gpt_evidence",
        "recommendation",
    ]

    existing_columns = [col for col in column_order if col in merged_df.columns]
    remaining_columns = [col for col in merged_df.columns if col not in existing_columns]

    return merged_df[existing_columns + remaining_columns]


def judge_detection_source(row) -> str:
    signature_detected = row["signature_detected"]
    gpt_detected = row["gpt_detected"]

    if signature_detected and gpt_detected:
        return "공통 탐지"

    if signature_detected and not gpt_detected:
        return "Signature 전용"

    if not signature_detected and gpt_detected:
        return "GPT 전용"

    return "판단불가"