<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.sql.*" %>
<%
    // 💡 폼에서 넘어온 파라미터 (name 속성에 맞춤)
    String id = request.getParameter("id");
    String pw = request.getParameter("pw");
    
    String errorMsg = null;

    if (id != null && pw != null) {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            // 사용자님의 MariaDB 접속 설정
            Class.forName("org.mariadb.jdbc.Driver");
            conn = DriverManager.getConnection(
                "jdbc:mariadb://localhost:3306/vuln_db",
                "vulnuser",
                "vulnpass1234"
            );

            stmt = conn.createStatement();

            // 🚨 실습용 취약 코드: 사용자의 입력을 검증 없이 쿼리에 연결
            String sql = "SELECT * FROM users WHERE username='" + id + "' AND password='" + pw + "'";
            rs = stmt.executeQuery(sql);

            if (rs.next()) {
		String role = rs.getString("role");
                // 💡 로그인 성공: DB의 username을 세션에 저장하고 메인으로 이동
                session.setAttribute("userId", rs.getString("username"));
		session.setAttribute("userNo", rs.getString("id"));
                session.setAttribute("userRole", rs.getString("role"));
		if("admin".equalsIgnoreCase(role)) {
			response.sendRedirect("admin.jsp");
		}
		else{
			response.sendRedirect("");
		}
                return; // HTML을 더 이상 그리지 않고 종료
            } else {
                // 💡 로그인 실패
                errorMsg = "아이디 또는 비밀번호가 일치하지 않습니다.";
            }

        } catch (Exception e) {
            // 통신 에러 발생 시 출력
            errorMsg = "데이터베이스 오류: " + e.getMessage();
        } finally {
            // 자원 반납
            try { if (rs != null) rs.close(); } catch(Exception e) {}
            try { if (stmt != null) stmt.close(); } catch(Exception e) {}
            try { if (conn != null) conn.close(); } catch(Exception e) {}
        }
    }
%>

<%@ include file="header.jsp" %>

    <h2>고객센터 로그인 (SQLi Test)</h2>
    <p style="margin-bottom: 1.5rem; color: #7f8c8d;">
        서비스 이용을 위해 로그인이 필요합니다.
    </p>

    <% if (errorMsg != null) { %>
        <div style="background-color: #f8d7da; color: #721c24; padding: 12px; border: 1px solid #f5c6cb; border-radius: 4px; margin-bottom: 1.5rem; font-weight: bold;">
            ⚠️ <%= errorMsg %>
        </div>
    <% } %>

    <form class="search-form" style="flex-direction: column;" method="POST" action="login.jsp">
        <input type="text" name="id" placeholder="아이디를 입력하세요" required>
        <input type="password" name="pw" placeholder="비밀번호를 입력하세요" required>
        <button type="submit" class="btn" style="width: 100%;">로그인</button>
    </form>

    <div style="margin-top: 15px; text-align: center;">
        <span style="color: #7f8c8d;">아직 계정이 없으신가요?</span> 
        <a href="register.jsp" style="color: #3498db; text-decoration: none; font-weight: bold; margin-left: 5px;">회원가입 하기</a>
    </div>
<%@ include file="footer.jsp" %>
