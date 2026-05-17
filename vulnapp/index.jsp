<%@ page contentType="text/html; charset=UTF-8" %>

<style>
    .test-list { list-style: none; padding: 0; display: flex; flex-direction: column; gap: 15px; }
    .test-card { 
        display: block; padding: 20px; background-color: #fff; border: 1px solid #e0e0e0; 
        border-radius: 8px; transition: all 0.2s ease-in-out; text-decoration: none; color: inherit;
    }
    .test-card:hover { 
        border-color: #3498db; box-shadow: 0 4px 12px rgba(52, 152, 219, 0.15); transform: translateY(-2px);
    }
    .test-title { font-size: 1.25rem; font-weight: bold; margin-bottom: 5px; }
    .test-desc { color: #7f8c8d; font-size: 0.95rem; margin: 0; }
</style>

<%@ include file="header.jsp" %>

    <div style="text-align: center; margin-bottom: 2.5rem; padding-top: 1rem;">
        <h1 style="color: #2c3e50; font-size: 2.2rem; margin-bottom: 10px;">🛡️ 4악다 Vulnerable Web App</h1>
        <p style="color: #7f8c8d; font-size: 1.1rem;">
            수동 진단과 자동 진단 비교를 위한 통합 웹 취약점 테스트 환경
        </p>
    </div>

    <div class="result-area" style="background-color: #fcf3f2; border-left: 5px solid #e74c3c; margin-bottom: 2rem;">
        <h3 style="color: #c0392b; margin-bottom: 10px;">🚨 실습 주의사항</h3>
        <p style="margin: 0; color: #555; line-height: 1.5;">
            본 웹사이트는 보안 교육 및 진단 실습을 목적으로 <strong>의도적인 취약점</strong>이 포함되어 있습니다.<br>
            학습 외의 목적으로 허가받지 않은 외부 시스템에 동일한 공격 기법을 시도하는 것은 정보통신망법에 의해 처벌받을 수 있습니다.
        </p>
    </div>

    <h2 style="margin-bottom: 1.5rem; border-bottom: 2px solid #ecf0f1; padding-bottom: 0.5rem;">🔥 취약점 진단 시나리오</h2>
    
    <ul class="test-list">
        <li>
            <a href="login.jsp" class="test-card">
                <div class="test-title" style="color: #2980b9;">🔑 SQL Injection Test</div>
                <p class="test-desc">로그인 페이지의 인증 로직을 우회하거나 데이터베이스의 정보를 추출하는 실습입니다.</p>
            </a>
        </li>
        <li>
            <a href="search.jsp" class="test-card">
                <div class="test-title" style="color: #27ae60;">🔍 Cross-Site Scripting (XSS) Test</div>
                <p class="test-desc">통합 검색창을 이용하여 클라이언트 브라우저에서 임의의 악성 스크립트를 실행하는 실습입니다.</p>
            </a>
        </li>
        <li>
            <a href="download.jsp" class="test-card">
                <div class="test-title" style="color: #c0392b;">💾 Path Traversal Test (자료실)</div>
                <p class="test-desc">파일 다운로드 기능의 경로 조작을 통해 서버 내부의 민감한 파일을 열람하는 실습입니다.</p>
            </a>
        </li>
        <li>
            <a href="debug.jsp" class="test-card">
                <div class="test-title" style="color: #f39c12;">📜 Sensitive Info Exposure Test</div>
                <p class="test-desc">개발 과정에서 남겨진 디버그 페이지를 통해 시스템 및 환경 설정 정보가 노출되는 실습입니다.</p>
            </a>
        </li>
        <li>
            <a href="admin.jsp" class="test-card">
                <div class="test-title" style="color: #8e44ad;">⚙️ Admin Page Exposure Test</div>
                <p class="test-desc">인가되지 않은 사용자가 취약한 접근 제어를 뚫고 관리자 전용 페이지에 접근하는 실습입니다.</p>
            </a>
        </li>
	<li>
            <a href="upload.jsp" class="test-card">
                <div class="test-title" style="color: #8e44ad;">📝 File upload Test</div>
                <p class="test-desc">파일 업로드 취약점(Unrestricted File Upload) 과 저장형 XSS(Stored XSS) 를 동시에 실습입니다.</p>
            </a>
        </li>
    </ul>

<%@ include file="footer.jsp" %>
