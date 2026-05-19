import os
from urllib.parse import urljoin

import requests

# 실제 백엔드 팀 서버 주소 (현재 사용)
BACKEND_BASE_URL = "http://15.164.60.79:8000"
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DOWNLOAD_DIR = os.path.join(BASE_DIR, "temp_downloads")
AUTO_RESULT_PATH = os.path.join(DOWNLOAD_DIR, "자동진단_결과.xlsx")


def _ensure_download_dir() -> None:
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def _save_stream_to_file(response: requests.Response, filepath: str) -> str:
    with open(filepath, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    return filepath


def _download_excel_file(file_url: str, filepath: str) -> str:
    response = requests.get(file_url, stream=True, timeout=600)
    response.raise_for_status()

    content_type = response.headers.get("Content-Type", "")
    if "spreadsheetml.sheet" not in content_type:
        raise RuntimeError(f"엑셀 파일 응답이 아닙니다: {response.text}")

    return _save_stream_to_file(response, filepath)


def _request_remote_scan(target_url: str, filepath: str) -> str:
    response = requests.post(
        f"{BACKEND_BASE_URL}/scan",
        json={"target": target_url},
        stream=True,
        timeout=600,
    )

    content_type = response.headers.get("Content-Type", "")

    if response.status_code != 200:
        error_msg = response.text
        raise RuntimeError(f"API 요청 실패 ({response.status_code}): {error_msg}")

    if "spreadsheetml.sheet" in content_type:
        return _save_stream_to_file(response, filepath)

    if "application/json" in content_type:
        result = response.json()
        auto_excel_url = result.get("auto_excel_url")
        if not auto_excel_url:
            raise RuntimeError(f"백엔드 JSON 응답에 auto_excel_url이 없습니다: {result}")
        return _download_excel_file(urljoin(f"{BACKEND_BASE_URL}/", auto_excel_url.lstrip("/")), filepath)

    raise RuntimeError(f"지원하지 않는 응답 형식입니다: {content_type or 'unknown'}")


def _run_local_scan(target_url: str) -> str:
    from main import run_gpt_vulnerability_scan

    generated_path = run_gpt_vulnerability_scan(target_url)
    with open(generated_path, "rb") as src, open(AUTO_RESULT_PATH, "wb") as dst:
        dst.write(src.read())
    return AUTO_RESULT_PATH


def request_scan_result(target_url: str):
    _ensure_download_dir()

    try:
        return _request_remote_scan(target_url, AUTO_RESULT_PATH)
    except Exception as remote_error:
        print(f"💡 [원격 진단 실패] {remote_error}")
        return _run_local_scan(target_url)

# import os
# import requests

# # 로컬(localhost) 대신 실제 백엔드 서버 주소로 변경합니다.
# BACKEND_BASE_URL = "http://15.164.60.79:8000"

# # 현재 내 컴퓨터에서 백엔드를 켜두었으므로 로컬 주소로 변경합니다.
# # BACKEND_BASE_URL = "http://127.0.0.1:8000"

# def request_scan_result(target_url: str):
#     """
#     FastAPI 서버에 진단을 요청하고, 결과 엑셀 파일(자동진단 1개)을 다운로드합니다.
#     """
#     # 1. API 서버에 진단 요청
#     response = requests.post(
#     f"{BACKEND_BASE_URL}/scan",
#     json={"target": target_url},
#     stream=True,
#     timeout=600  
#     )
#     response.raise_for_status()
    
#     # 2. JSON 응답에서 자동 진단 다운로드 URL 추출
#     result = response.json()
#     auto_excel_url = BACKEND_BASE_URL + result["auto_excel_url"]

#     # 3. 엑셀을 물리적으로 저장할 임시 폴더 및 파일 경로 설정
#     os.makedirs("temp_downloads", exist_ok=True)
#     auto_filepath = "temp_downloads/자동진단_결과.xlsx"

#     # 4. 스트림(Stream) 방식으로 안전하게 파일 다운로드 및 검증
#     file_response = requests.get(auto_excel_url, stream=True, timeout=60)
#     file_response.raise_for_status()

#     content_type = file_response.headers.get("Content-Type", "")
#     if "spreadsheetml.sheet" not in content_type:
#         body = file_response.text
#         raise RuntimeError(f"엑셀 파일 응답이 아닙니다:\n{body}")

#     # 5. 8192 바이트씩 청크 단위로 파일 저장 (유저 제공 로직 적용)
#     with open(auto_filepath, "wb") as f:
#         for chunk in file_response.iter_content(chunk_size=8192):
#             if chunk:
#                 f.write(chunk)

#     # 6. 다운로드가 완료된 파일의 경로를 반환
#     return auto_filepath
