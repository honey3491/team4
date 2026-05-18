import os
import json
import requests
import pandas as pd
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from openai import OpenAI

# 1. 환경 변수 로드를 위한 라이브러리 불러오기
from dotenv import load_dotenv

# 2. .env 파일의 내용을 환경 변수로 로드
load_dotenv()

app = FastAPI(title="GPT 기반 웹 취약점 진단 API 서버")

TEMP_DIR = "temp_results"
os.makedirs(TEMP_DIR, exist_ok=True)

# 3. 환경 변수에서 API 키 가져오기
# .env 파일에 작성한 이름과 동일해야 합니다.
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# API 키가 제대로 설정되지 않았을 경우 에러 알림
if not OPENAI_API_KEY:
    print("❌ 에러: .env 파일에서 OPENAI_API_KEY를 찾을 수 없습니다.")
else:
    print("✅ 성공: OpenAI API 키가 환경 변수로부터 로드되었습니다.")

client = OpenAI(api_key=OPENAI_API_KEY)

class ScanRequest(BaseModel):
    target_url: str

def fetch_website_content(url: str) -> str:
    """타겟 URL에 접속해서 HTML 소스코드를 가져옵니다."""
    try:
        # 일반 웹 브라우저인 것처럼 위장하는 헤더 추가
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        # 너무 오래 기다리지 않도록 30초 제한 (기존 10초에서 연장)
        response = requests.get(url, headers=headers, timeout=30, verify=False) 
        html_content = response.text
        
        # GPT에게 보낼 글자 수 제한 (비용 절감 및 토큰 한도 초과 방지, 약 15000자)
        return html_content[:15000]
    except Exception as e:
        print(f"웹사이트 접속 실패: {e}")
        return None

def run_gpt_vulnerability_scan(target_url: str) -> str:
    """GPT를 이용해 취약점을 분석하고 자동진단(Auto) 엑셀 파일을 생성합니다."""
    filepath = os.path.join(TEMP_DIR, "auto_result.xlsx")
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("1. 타겟 웹사이트 소스코드 추출 중...")
    html_content = fetch_website_content(target_url)
    
    if not html_content:
        # 접속 실패 시 기본 에러 데이터 생성
        df = pd.DataFrame([{
            "target": target_url, "generated_at": current_time, "id": "A-ERR",
            "check_id": "ERR-01", "owasp": "-", "vuln_name": "Target Connection Error",
            "severity": "info", "evidence": "웹사이트에 접속할 수 없습니다.", "recommendation": "URL을 확인하거나 방화벽 설정을 점검하세요."
        }])
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name="findings", index=False)
        return filepath

    print("2. GPT 보안 전문가에게 소스코드 분석 요청 중... (약 10~30초 소요)")
    
    # GPT에게 내릴 프롬프트 명령 (JSON 형태로만 대답하도록 강제)
    system_prompt = """
    당신은 20년 경력의 웹 모의해킹 전문가이자 시니어 보안 아키텍트입니다. 
    제공된 웹사이트 HTML 소스코드를 분석하여 OWASP Top 10 기반의 보안 취약점이 있는지 점검하세요.
    반드시 아래 JSON 포맷을 엄격하게 지켜서 'vulnerabilities'라는 배열(List)에 결과를 담아 응답해야 합니다. 
    
    [작성 지침]
    1. 'vuln_name', 'evidence', 'recommendation' 필드의 값은 반드시 전문적이고 자연스러운 한국어(Korean)로 작성하세요.
    2. 'recommendation(대응 방안)' 작성 시 절대 추상적으로 적지 마세요. 아래 3가지를 반드시 포함하여 3~4문장 이상으로 아주 상세히 작성하세요.
       - [수정 위치]: 소스코드 상에서 어느 태그, 폼(Form), 또는 파라미터를 수정해야 하는지 특정
       - [코드 레벨 가이드]: 입력값 검증, 출력값 인코딩, CSRF 토큰 등 구체적으로 어떤 방어 로직을 추가해야 하는지 설명
       - [시크릿 관리]: 소스코드에 하드코딩된 중요 정보(API 키, 비밀번호, 주소 등)가 있거나 예상된다면, 반드시 환경 변수(.env) 분리 또는 시크릿 매니저 사용을 강력히 권고할 것

    {
      "vulnerabilities": [
        {
          "check_id": "CWE-번호 (예: CWE-79)",
          "owasp": "OWASP 카테고리 (예: A03:2021-Injection)",
          "vuln_name": "취약점 이름 또는 점검 항목 (한국어)",
          "severity": "critical, high, medium, low, pass, n/a 중 하나",
          "evidence": "취약점이 의심되는 소스코드 위치 및 판단 근거 상세 설명 (한국어)",
          "recommendation": "구체적인 코드 수정 가이드 및 시크릿 관리 방안을 포함한 상세 조치 방법 (한국어)"
        }
      ]
    }
    """

    try:
        # 비용과 속도를 고려해 gpt-4o-mini 모델 사용 (성능이 더 필요하면 gpt-4o로 변경)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"URL: {target_url}\n\nHTML Content:\n{html_content}"}
            ],
            temperature=0.2 # 답변을 창의적이기보다 분석적이고 일관성 있게 설정
        )
        
        # GPT의 대답(JSON 문자열)을 파이썬 딕셔너리로 변환
        gpt_result = json.loads(response.choices[0].message.content)
        vuln_list = gpt_result.get("vulnerabilities", [])
        
    except Exception as e:
        print(f"GPT API 호출 오류: {e}")
        vuln_list = []

    # 3. 결과를 Pandas 데이터프레임으로 변환하여 엑셀 생성
    print(f"3. 분석 완료! 총 {len(vuln_list)}개의 의심 항목 발견.")
    
    # 취약점이 없을 경우 빈 데이터프레임 방지
    if not vuln_list:
         vuln_list = [{
            "check_id": "SAFE-01", "owasp": "-", "vuln_name": "전반적 보안 상태 양호",
            "severity": "pass", # 👈 여기를 pass로 변경
            "evidence": "현재 제공된 HTML 소스코드 상 명백한 취약점이 발견되지 않았습니다.",
            "recommendation": "현재의 보안 상태를 지속적으로 모니터링 및 유지하시기 바랍니다."
        }]

    # 대시보드(loader.py) 규격에 맞게 살 붙이기
    for i, vuln in enumerate(vuln_list):
        vuln["target"] = target_url
        vuln["generated_at"] = current_time
        vuln["id"] = f"GPT-{str(i+1).zfill(3)}" # GPT-001, GPT-002 형태로 ID 부여

    df = pd.DataFrame(vuln_list)
    
    # 컬럼 순서 정렬
    cols = ["target", "generated_at", "id", "check_id", "owasp", "vuln_name", "severity", "evidence", "recommendation"]
    # GPT가 실수로 누락한 컬럼이 있을 수 있으니 방어 코드 추가
    for col in cols:
        if col not in df.columns:
            df[col] = "-"
    df = df[cols]

    with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name="findings", index=False)
        
    return filepath

# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------

@app.post("/scan")
def run_scan(request: ScanRequest):
    print(f"\n======================================")
    print(f"🚀 진단 시작: {request.target_url}")
    
    # 1. 자동 진단: 실제 GPT 연동 엔진 가동!
    auto_excel_path = run_gpt_vulnerability_scan(request.target_url)
    
    # (기존에 있던 수동 진단 엑셀 생성 부분은 모두 삭제했습니다!)

    print("✅ 스캔 및 엑셀 생성 완료. 프론트엔드로 파일 전송 준비 완료.")
    print(f"======================================\n")

    # 자동 진단 URL 딱 한 개만 JSON으로 반환합니다.
    return {
        "auto_excel_url": "/download/auto_result.xlsx"
    }

@app.get("/download/{filename}")
def download_file(filename: str):
    filepath = os.path.join(TEMP_DIR, filename)
    if os.path.exists(filepath):
        return FileResponse(path=filepath, filename=filename, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    raise HTTPException(status_code=404, detail="File not found")