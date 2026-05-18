<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.sql.*" %>

<%-- 💡 공통 헤더 포함 --%>
<%@ include file="header.jsp" %>

<%
    request.setCharacterEncoding("UTF-8");
    String keyword = request.getParameter("keyword");
    if (keyword == null) keyword = ""; // null 방지

    // DB 연결 설정
    Connection conn = null;
    PreparedStatement pstmt = null;
    ResultSet rs = null;
%>

    <div style="border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; margin-bottom: 20px;">
        <h2 style="margin: 0; color: #2980b9;">🔍 통합 검색 및 게시판</h2>
    </div>

    <div style="margin-bottom: 30px; background: #f8f9fa; padding: 20px; border-radius: 8px;">
        <form action="search.jsp" method="GET" style="display: flex; gap: 10px;">
            <input type="text" name="keyword" value="<%= keyword %>" placeholder="검색어를 입력하세요..." 
                   style="flex-grow: 1; padding: 10px; border: 1px solid #ccc; border-radius: 4px;">
            <button type="submit" style="background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                검색
            </button>
        </form>
        
        <% if (!keyword.equals("")) { %>
            <p style="margin-top: 15px; color: #555;">
                <strong>'<%= keyword %>'</strong> 에 대한 검색 결과입니다. 
                <span style="color: #e74c3c;">(🚨 Reflected XSS 취약점 포인트)</span>
            </p>
        <% } %>
    </div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
        <h3 style="margin: 0;">📋 최근 게시물</h3>
        <a href="upload.jsp" style="background: #27ae60; color: white; text-decoration: none; padding: 8px 15px; border-radius: 4px; font-size: 0.9em; font-weight: bold;">
            새 글 쓰기
        </a>
    </div>

    <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
        <thead>
            <tr style="background: #2c3e50; color: white; text-align: left;">
                <th style="padding: 12px; border: 1px solid #dee2e6;">ID</th>
                <th style="padding: 12px; border: 1px solid #dee2e6; width: 40%;">제목</th>
                <th style="padding: 12px; border: 1px solid #dee2e6;">작성자</th>
                <th style="padding: 12px; border: 1px solid #dee2e6;">첨부파일</th>
                <th style="padding: 12px; border: 1px solid #dee2e6;">날짜</th>
            </tr>
        </thead>
        <tbody>
<%
    try {
        Class.forName("org.mariadb.jdbc.Driver");
        conn = DriverManager.getConnection("jdbc:mariadb://mariadb.cinwlvqqoprv.ap-northeast-2.rds.amazonaws.com:3306/vuln_db", "vulnuser", "vulnpass1234");

        // 검색어가 있으면 필터링, 없으면 전체 조회 (SQL Injection 실습을 원하면 Statement로 변경 가능)
        String sql = "SELECT * FROM posts WHERE title LIKE ? OR content LIKE ? ORDER BY id DESC";
        pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, "%" + keyword + "%");
        pstmt.setString(2, "%" + keyword + "%");
        rs = pstmt.executeQuery();

        boolean hasResult = false;
        while (rs.next()) {
            hasResult = true;
%>
            <tr style="border-bottom: 1px solid #eee;">
                <td style="padding: 12px; border: 1px solid #dee2e6; text-align: center;"><%= rs.getInt("id") %></td>
                <td style="padding: 12px; border: 1px solid #dee2e6;">
                    <a href="view.jsp?postid=<%= rs.getInt("id") %>" style="color: #2c3e50; font-weight: bold; text-decoration: none;">
                        <%= rs.getString("title") %> </a>
                </td>
                <td style="padding: 12px; border: 1px solid #dee2e6; text-align: center;"><%= rs.getString("author") %></td>
                <td style="padding: 12px; border: 1px solid #dee2e6; text-align: center;">
                    <% if (rs.getString("filename") != null && !rs.getString("filename").isEmpty()) { %>
                        <span title="<%= rs.getString("filename") %>">💾</span>
                    <% } %>
                </td>
                <td style="padding: 12px; border: 1px solid #dee2e6; font-size: 0.85em; color: #7f8c8d;"><%= rs.getTimestamp("reg_date") %></td>
            </tr>
<%
        }
        if (!hasResult) {
            out.println("<tr><td colspan='5' style='padding:30px; text-align:center; color:#999;'>검색 결과가 없습니다.</td></tr>");
        }
    } catch (Exception e) {
        out.println("<tr><td colspan='5' style='padding:30px; color:red;'>에러 발생: " + e.getMessage() + "</td></tr>");
    } finally {
        if (rs != null) try { rs.close(); } catch(Exception e) {}
        if (pstmt != null) try { pstmt.close(); } catch(Exception e) {}
        if (conn != null) try { conn.close(); } catch(Exception e) {}
    }
%>
        </tbody>
    </table>

<%-- 💡 공통 푸터 포함 --%>
<%@ include file="footer.jsp" %>
