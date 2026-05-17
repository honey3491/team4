<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.sql.*" %>

<%!
    private boolean isPasswordStrong(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasUpperCase = password.matches(".*[A-Z].*");
        boolean hasLowerCase = password.matches(".*[a-z].*");
        boolean hasNumber = password.matches(".*[0-9].*");
        boolean hasSpecialChar = password.matches(".*[!@#$%^&*(),.?\":{}|<>].*");

        return hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
    }
%>

<%
    request.setCharacterEncoding("UTF-8");

    String regId = request.getParameter("regId");
    String regName = request.getParameter("regName");
    String regPw = request.getParameter("regPw");
    String regRole = request.getParameter("regRole");

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

            if (!isPasswordStrong(regPw)) {
                msg = "❌ 비밀번호는 8자 이상이며, 대문자·소문자·숫자·특수문자를 모두 포함해야 합니다.";
            } else {
                String checkSql = "SELECT id FROM users WHERE username = ?";
                pstmt = conn.prepareStatement(checkSql);
                pstmt.setString(1, regId);
                rs = pstmt.executeQuery();

                if (rs.next()) {
                    msg = "❌ 이미 존재하는 아이디입니다.";
                } else {
                    pstmt.close();

                    if (regRole == null || regRole.trim().isEmpty()) {
                        regRole = "user";
                    }

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

<h2>회원가입</h2>
<p style="margin-bottom: 1.5rem; color: #7f8c8d;">
    대문자, 소문자, 숫자, 특수문자를 포함한 8자 이상의 비밀번호만 사용할 수 있습니다.
</p>

<% if (msg != null) { %>
    <div style="background-color: <%= isSuccess ? "#d4edda" : "#f8d7da" %>;
                color: <%= isSuccess ? "#155724" : "#721c24" %>;
                padding: 12px;
                border: 1px solid <%= isSuccess ? "#c3e6cb" : "#f5c6cb" %>;
                border-radius: 4px;
                margin-bottom: 1.5rem;
                font-weight: bold;">
        <%= msg %>
    </div>
<% } %>

<% if (!isSuccess) { %>
    <form class="search-form" style="flex-direction: column;" method="POST" action="register.jsp" onsubmit="return validateForm();">

        <div style="margin-bottom: 10px; width: 100%;">
            <label style="font-weight: bold; display: block; margin-bottom: 5px;">아이디</label>
            <input type="text" name="regId" placeholder="사용할 아이디를 입력하세요" required style="width: 100%;">
        </div>

        <div style="margin-bottom: 10px; width: 100%;">
            <label style="font-weight: bold; display: block; margin-bottom: 5px;">사용자명</label>
            <input type="text" name="regName" placeholder="실명 또는 닉네임을 입력하세요" required style="width: 100%;">
        </div>

        <div style="margin-bottom: 10px; width: 100%;">
            <label style="font-weight: bold; display: block; margin-bottom: 5px;">비밀번호</label>
            <input type="password" id="regPw" name="regPw" placeholder="예: Test123!" required style="width: 100%;">
            <span id="strengthText" style="font-size: 0.85em; display: block; margin-top: 5px; font-weight: bold;"></span>
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
    const strengthText = document.getElementById('strengthText');

    function isPasswordStrong(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        return password.length >= minLength &&
               hasUpperCase &&
               hasLowerCase &&
               hasNumber &&
               hasSpecialChar;
    }

    function checkPasswordStrength() {
        const password = pwInput.value;

        if (password === "") {
            strengthText.textContent = "";
            return;
        }

        if (isPasswordStrong(password)) {
            strengthText.style.color = "#27ae60";
            strengthText.textContent = "Strength: Strong";
        } else {
            strengthText.style.color = "#c0392b";
            strengthText.textContent = "Strength: Weak - 8자 이상, 대문자, 소문자, 숫자, 특수문자를 포함해야 합니다.";
        }
    }

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

    pwInput.addEventListener('input', function() {
        checkPasswordStrength();
        checkPasswordMatch();
    });

    pwCheckInput.addEventListener('input', checkPasswordMatch);

    function validateForm() {
        if (!isPasswordStrong(pwInput.value)) {
            alert("비밀번호는 8자 이상이며, 대문자·소문자·숫자·특수문자를 모두 포함해야 합니다.");
            pwInput.focus();
            return false;
        }

        if (pwInput.value !== pwCheckInput.value) {
            alert("비밀번호가 서로 일치하지 않습니다.");
            pwCheckInput.focus();
            return false;
        }

        return true;
    }
</script>

<%@ include file="footer.jsp" %>
