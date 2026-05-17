# GPT 기반 웹 취약점 자동 진단 서비스

## Docker 실행

```bash
docker compose up -d --build
```

API:

```text
http://EC2_PUBLIC_IP:8000/scan
```

예시:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://15.164.60.79"}'
```

## 1. 프로젝트 개요

외부 진단 PC에서 대상 웹서비스에 HTTP 요청을 보내 응답 헤더, 상태코드, 응답 본문, 테스트 페이로드 결과를 수집하고, GPT가 이를 분석하여 10개 취약점 항목에 대해 취약/양호/N/A, 판단 근거, 위험도, 대응 방안을 생성한다.

## 2. 폴더 구조

```text
gpt-vuln-scanner/
├── gpt_based_scanner.py
├── .env
├── .env.example
├── .gitignore
├── requirements.txt
├── outputs/
└── manual/
