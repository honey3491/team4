import os
import requests

# 실제 백엔드 팀 서버 주소 (현재 사용)
BACKEND_BASE_URL = "http://15.164.60.79:8000"

def request_scan_result(target_url: str):
    os.makedirs("temp_downloads", exist_ok=True)
    auto_filepath = "temp_downloads/자동진단_결과.xlsx"

    # 1. API 서버에 원스텝 진단 요청
    response = requests.post(
        f"{BACKEND_BASE_URL}/scan",
        json={"target": target_url},  # 백엔드가 요구한 "target" 변수명
        stream=True,
        timeout=600  
    )
    
    # 2. 에러 상세 디버깅 로직 (에러 발생 시 json 대신 text로 안전하게 확인)
    if response.status_code != 200:
        error_msg = response.text
        print(f"💡 [에러 발생] 상태 코드: {response.status_code}")
        print(f"💡 [에러 상세] {error_msg}")
        raise RuntimeError(f"API 요청 실패 ({response.status_code}): {error_msg}")

    # 3. 응답 헤더 검증 (엑셀 파일이 맞는지 확인)
    content_type = response.headers.get("Content-Type", "")
    if "spreadsheetml.sheet" not in content_type:
        body = response.text
        raise RuntimeError(f"서버가 엑셀 파일이 아닌 다른 데이터를 응답했습니다:\n{body}")

    # 4. 파일 저장
    with open(auto_filepath, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    return auto_filepath

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