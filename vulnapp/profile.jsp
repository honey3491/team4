<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.sql.*" %>
<%
    // URL에서 user_idx 파라미터 값을 가져옴
    String userIdx = request.getParameter("user_idx");
    
    String userInfo = "";
    String userRole = "";
    boolean hasError = false;

    if (userIdx != null && !userIdx.trim().isEmpty()) {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            Class.forName("org.mariadb.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mariadb://localhost:3306/vuln_db", "vulnuser", "vulnpass1234");
            stmt = conn.createStatement();

            // 🚨 취약점 포인트: 입력값을 검증 없이 쿼리에 직접 삽입 (IDOR 및 SQL Injection 발생 가능)
            String sql = "SELECT * FROM users WHERE id = " + userIdx;
            rs = stmt.executeQuery(sql);

            if (rs.next()) {
                userInfo = rs.getString("username");
                userRole = rs.getString("role");
            } else {
                userInfo = "존재하지 않는 회원 번호입니다.";
                hasError = true;
            }
        } catch (Exception e) {
            userInfo = "데이터베이스 오류: " + e.getMessage();
            hasError = true;
        } finally {
            try { if (rs != null) rs.close(); } catch(Exception e) {}
            try { if (stmt != null) stmt.close(); } catch(Exception e) {}
            try { if (conn != null) conn.close(); } catch(Exception e) {}
        }
    } else {
        userInfo = "잘못된 접근입니다. URL에 회원 번호(user_idx)가 필요합니다.";
        hasError = true;
    }
%>

<%@ include file="header.jsp" %>

    <h2>마이페이지 (IDOR Test)</h2>
    <p style="margin-bottom: 1.5rem; color: #7f8c8d;">
        회원님의 상세 정보를 확인하는 페이지입니다.
    </p>

    <% if (hasError) { %>
        <div style="background-color: #f8d7da; color: #721c24; padding: 12px; border: 1px solid #f5c6cb; border-radius: 4px; margin-bottom: 1.5rem; font-weight: bold;">
            ⚠️ <%= userInfo %>
            <% if (userIdx == null || userIdx.trim().isEmpty()) { %>
                <br><br>
                <span style="font-weight: normal; font-size: 0.9em;">
                    👉 <strong>테스트 힌트:</strong> 브라우저 주소창 끝에 <code>?user_idx=1</code> 을 추가해 보세요.
                </span>
            <% } %>
        </div>
    <% } else { %>
        <div class="result-area" style="background-color: #fff; border: 1px solid #e0e0e0; border-left: 5px solid #2ecc71;">
            <ul style="list-style-type: none; padding: 0;">
                <li style="margin-bottom: 12px; font-size: 1.1em;">
                    <strong>회원 번호 (id):</strong> <span style="color: #3498db;"><%= userIdx %></span>
                </li>
                <li style="margin-bottom: 12px; font-size: 1.1em;">
                    <strong>사용자 ID:</strong> <%= userInfo %>
                </li>
                <li style="font-size: 1.1em;">
                    <strong>권한 레벨:</strong> 
                    <% if ("admin".equalsIgnoreCase(userRole)) { %>
                        <span style="color: #e74c3c; font-weight: bold;"><%= userRole %> 👑</span>
                    <% } else { %>
                        <span style="color: #27ae60; font-weight: bold;"><%= userRole %></span>
                    <% } %>
                </li>
            </ul>
        </div>
    <% } %>

<%@ include file="footer.jsp" %>
