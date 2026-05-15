# Thorium-inspired URL Vulnerability Scanner + AI Analyzer

웹사이트 URL을 입력하면 직접 접속하여 비파괴적 취약점 진단을 수행하는 경량 자동화 도구다.

## 진단 기능

- Alive Check
- Security Header Misconfiguration
- Server Banner Disclosure
- Sensitive Path Exposure
- Directory Listing
- Reflected XSS
- SQL Injection Error-based Signal
- Directory Traversal Signal
- Command Injection Reflection Signal
- Form Discovery
- CVE Keyword Lookup
- OpenAI 기반 사고 분석/대응 방안 생성
- Streamlit Dashboard

## 실행

```bash
cp .env.example .env
nano .env
mkdir -p data
docker compose up -d --build
```

Dashboard:

```text
http://EC2_PUBLIC_IP:8501
```

API:

```text
http://EC2_PUBLIC_IP:8000/docs
```

## 직접 API 테스트

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url":"http://testphp.vulnweb.com/listproducts.php?cat=1"}'
```

## 주의

본인 소유 또는 명시적으로 허가받은 사이트에만 사용한다.
