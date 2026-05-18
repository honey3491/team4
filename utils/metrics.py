import pandas as pd


def calculate_metrics(manual_df: pd.DataFrame, auto_df: pd.DataFrame) -> dict:
    combined_df = pd.concat([manual_df, auto_df], ignore_index=True)

    total_count = len(combined_df)
    manual_count = len(manual_df)
    auto_count = len(auto_df)

    severity_counts = combined_df["severity"].value_counts().to_dict()

    critical_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    medium_count = severity_counts.get("medium", 0)
    low_count = severity_counts.get("low", 0)
    pass_count = severity_counts.get("pass", 0)
    na_count = severity_counts.get("n/a", 0)

    return {
        "total_count": total_count,
        "manual_count": manual_count,
        "auto_count": auto_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "pass_count": pass_count,
        "na_count": na_count,
        "severity_counts": severity_counts,
    }