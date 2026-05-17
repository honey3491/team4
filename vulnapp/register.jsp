<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.sql.*" %>
<%
    request.setCharacterEncoding("UTF-8");
    String regId = request.getParameter("regId");       // 로그인용 ID
    String regName = request.getParameter("regName");   // 사용자 이름/닉네임
    String regPw = request.getParameter("regPw");       // 비밀번호
    String regRole = request.getParameter("regRole");   // 권한

    String msg = null;
    boolean isSuccess = false;

    if (regId != null && regPw != null && regName != null) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            Class.forName("org.mariadb.jdbc.Driver");
            conn = DriverManager.getConnection(
                "jdbc:mariadb://localhost:3306/vuln_db",
                "vulnuser",
                "vulnpass1234"
            );

            // 1. 아이디 중복 체크
            String checkSql = "SELECT id FROM users WHERE username = ?";
            pstmt = conn.prepareStatement(checkSql);
            pstmt.setString(1, regId);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                msg = "❌ 이미 존재하는 아이디입니다.";
            } else {
                pstmt.close();

                // 2. 권한 기본값 설정 (취약점 유지)
                if (regRole == null || regRole.trim().isEmpty()) {
                    regRole = "user";
                }

                // 3. 회원가입 진행 (여기서 regName을 테이블 구조에 맞게 바인딩합니다)
                // 💡 만약 테이블 컬럼명이 다르면 설정을 확인하세요 (예: 실제이름 컬럼이 따로 없다면 username 자리에 regName을 넣거나 조절)
                String insertSql = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
                pstmt = conn.prepareStatement(insertSql);
                pstmt.setString(1, regId);
                pstmt.setString(2, regPw);
                pstmt.setString(3, regRole);

                int result = pstmt.executeUpdate();
                if (result >= 1) {
                    msg = "🎉 회원가입이 완료되었습니다! 로그인해 주세요.";
                    isSuccess = true;
                }
            }
        } catch (Exception e) {
            msg = "데이터베이스 오류: " + e.getMessage();
        } finally {
            try { if (rs != null) rs.close(); } catch(Exception e) {}
            try { if (pstmt != null) pstmt.close(); } catch(Exception e) {}
            try { if (conn != null) conn.close(); } catch(Exception e) {}
        }
    }
%>

<%@ include file="header.jsp" %>

    <h2>회원가입 (Form Validation Test)</h2>
    <p style="margin-bottom: 1.5rem; color: #7f8c8d;">
        새로운 계정을 생성합니다. 모든 항목을 입력해 주세요.
    </p>

    <% if (msg != null) { %>
        <div style="background-color: <%= isSuccess ? "#d4edda" : "#f8d7da" %>; 
                    color: <%= isSuccess ? "#155724" : "#721c24" %>; 
                    padding: 12px; 
                    border: 1px solid <%= isSuccess ? "#c3e6cb" : "#f5c6cb" %>; 
                    border-radius: 4px; margin-bottom: 1.5rem; font-weight: bold;">
            <%= msg %>
        </div>
    <% } %>

    <% if (!isSuccess) { %>
        <form class="search-form" style="flex-direction: column;" method="POST" action="register.jsp" onsubmit="return validateForm();">
            
            <div style="margin-bottom: 10px; width: 100%;">
                <label style="font-weight: bold; display: block; margin-bottom: 5px;">아이디 (로그인 ID)</label>
                <input type="text" name="regId" placeholder="사용할 아이디를 입력하세요" required style="width: 100%;">
            </div>

            <div style="margin-bottom: 10px; width: 100%;">
                <label style="font-weight: bold; display: block; margin-bottom: 5px;">사용자명 (이름 또는 닉네임)</label>
                <input type="text" name="regName" placeholder="실명 또는 닉네임을 입력하세요" required style="width: 100%;">
            </div>
            
            <div style="margin-bottom: 10px; width: 100%;">
                <label style="font-weight: bold; display: block; margin-bottom: 5px;">비밀번호</label>
                <input type="password" id="regPw" name="regPw" placeholder="사용할 비밀번호를 입력하세요" required style="width: 100%;">
            </div>

            <div style="margin-bottom: 15px; width: 100%;">
                <label style="font-weight: bold; display: block; margin-bottom: 5px;">비밀번호 확인</label>
                <input type="password" id="regPwCheck" placeholder="비밀번호를 한 번 더 입력하세요" required style="width: 100%;">
                <span id="pwMatchMessage" style="font-size: 0.85em; display: block; margin-top: 5px; font-weight: bold;"></span>
            </div>

            <input type="hidden" name="regRole" value="user">

            <button type="submit" class="btn" style="width: 100%; background-color: #2980b9;">가입하기</button>
        </form>
    <% } %>

    <div style="margin-top: 15px; text-align: center;">
        <a href="login.jsp" style="color: #7f8c8d; text-decoration: none;">◀ 로그인 화면으로 돌아가기</a>
    </div>

    <script>
        const pwInput = document.getElementById('regPw');
        const pwCheckInput = document.getElementById('regPwCheck');
        const matchMessage = document.getElementById('pwMatchMessage');

        function checkPasswordMatch() {
            if (pwCheckInput.value === "") {
                matchMessage.textContent = "";
                return;
            }
            
            if (pwInput.value === pwCheckInput.value) {
                matchMessage.style.color = "#27ae60";
                matchMessage.textContent = "✓ 비밀번호가 일치합니다.";
            } else {
                matchMessage.style.color = "#c0392b";
                matchMessage.textContent = "✗ 비밀번호가 일치하지 않습니다.";
            }
        }

        // 사용자가 타이핑할 때마다 실시간 검사
        pwInput.addEventListener('input', checkPasswordMatch);
        pwCheckInput.addEventListener('input', checkPasswordMatch);

        // 폼 전송 시 최종 검사 수행
        function validateForm() {
            if (pwInput.value !== pwCheckInput.value) {
                alert("비밀번호가 서로 일치하지 않습니다. 다시 확인해 주세요.");
                pwCheckInput.focus();
                return false; // 전송 중단
            }
            return true; // 전송 허용
        }
    </script>

<%@ include file="footer.jsp" %>
