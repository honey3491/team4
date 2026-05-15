<%@ page import="java.sql.*" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<%
    // URL에서 user_idx 파라미터 값을 가져옴 (예: ?user_idx=1 이면 "1" 저장)
    String userIdx = request.getParameter("user_idx");
    
    String userInfo = "";
    String userRole = "";

    if (userIdx != null && !userIdx.trim().isEmpty()) {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            Class.forName("org.mariadb.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mariadb://localhost:3306/vuln_db", "vulnuser", "vulnpass1234");
            stmt = conn.createStatement();

            // 🚨 취약점 포인트: 사용자가 입력한 번호(userIdx)를 아무 검증 없이 그대로 쿼리에 넣음
            String sql = "SELECT * FROM users WHERE id = " + userIdx;
            rs = stmt.executeQuery(sql);

            if (rs.next()) {
                userInfo = rs.getString("username");
                userRole = rs.getString("role");
            } else {
                userInfo = "존재하지 않는 회원 번호입니다.";
            }
        } catch (Exception e) {
            userInfo = "Error: " + e.getMessage();
        } finally {
            try { if (rs != null) rs.close(); } catch(Exception e) {}
            try { if (stmt != null) stmt.close(); } catch(Exception e) {}
            try { if (conn != null) conn.close(); } catch(Exception e) {}
        }
    } else {
        userInfo = "잘못된 접근입니다. URL에 회원 번호(user_idx)가 필요합니다.";
    }
%>

<html>
<head>
    <title>User Profile (IDOR Test)</title>
</head>
<body>
    <h2>마이페이지 (My Profile)</h2>
    <hr>
    <% if (userRole.equals("")) { %>
        <p><%= userInfo %></p>
    <% } else { %>
        <ul>
            <li><strong>회원 번호 (id):</strong> <%= userIdx %></li>
            <li><strong>사용자 ID:</strong> <%= userInfo %></li>
            <li><strong>권한 레벨:</strong> <%= userRole %></li>
        </ul>
        
        <br>
        </fieldset>

    <% } %>
</body>
</html>
