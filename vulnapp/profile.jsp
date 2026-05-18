<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="javax.servlet.ServletException" %>
<%@ page import="java.sql.*" %>
<%-- 💡 header.jsp를 가장 먼저 포함시켜서 userId, userNo, userRole 변수를 확보합니다. --%>
<%@ include file="header.jsp" %>

<%
    // 1. 변수 초기화
    // URL 파라미터에서 user_idx를 가져옵니다. (없으면 null)
    String userIdx = request.getParameter("user_idx");
    
    String userInfo = ""; // 사용자 이름을 담을 변수
    String targetRole = ""; // 조회된 사용자의 권한을 담을 변수
    boolean hasError = false;

    // 2. 로직 처리
    // URL에 user_idx 파라미터가 있는지 확인합니다.
    if (userIdx != null && !userIdx.trim().isEmpty()) {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            Class.forName("org.mariadb.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mariadb://mariadb.cinwlvqqoprv.ap-northeast-2.rds.amazonaws.com:3306/vuln_db", "vulnuser", "vulnpass1234");
            stmt = conn.createStatement();

            // 🚨 취약점 포인트: 입력값(userIdx)을 검증 없이 쿼리에 직접 삽입 (IDOR 실습용)
            String sql = "SELECT * FROM users WHERE id = " + userIdx;
            rs = stmt.executeQuery(sql);

            if (rs.next()) {
                userInfo = rs.getString("username");
                targetRole = rs.getString("role");
            } else {
                userInfo = "존재하지 않는 회원 번호입니다.";
                hasError = true;
            }
        } catch (Exception e) {
            throw new ServletException("프로필 조회 중 데이터베이스 오류가 발생했습니다.", e);
        } finally {
            try { if (rs != null) rs.close(); } catch(Exception e) {}
            try { if (stmt != null) stmt.close(); } catch(Exception e) {}
            try { if (conn != null) conn.close(); } catch(Exception e) {}
        }
    } else {
        // 파라미터가 아예 없는 경우
        userInfo = "잘못된 접근입니다. URL에 회원 번호(user_idx)가 필요합니다.";
        hasError = true;
    }
%>

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
                    👉 <strong>테스트 힌트:</strong> 브라우저 주소창 끝에 <code>?user_idx=<%= (userNo != null) ? userNo : "1" %></code> 을 추가해 보세요.
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
                    <%-- 내 세션 정보(userRole)가 아니라, DB에서 방금 조회한 대상의 권한(targetRole)을 출력해야 함 --%>
                    <% if ("admin".equalsIgnoreCase(targetRole)) { %>
                        <span style="color: #e74c3c; font-weight: bold;"><%= targetRole %> 👑</span>
                    <% } else { %>
                        <span style="color: #27ae60; font-weight: bold;"><%= targetRole %></span>
                    <% } %>
                </li>
            </ul>
        </div>
    <% } %>

<%@ include file="footer.jsp" %>

