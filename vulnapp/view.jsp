
<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.sql.*" %>

<%-- 공통 헤더 포함 --%>
<%@ include file="header.jsp" %>

<%
    request.setCharacterEncoding("UTF-8");
    
    // 💡 세션에서 현재 로그인한 사용자의 권한 정보 가져오기
    String userRole = (String) session.getAttribute("userRole");
    if (userRole == null) {
        userRole = "guest"; // 🛡️ 로그인하지 않은 사용자는 'guest'로 취급하여 NullPointerException 방지
    }
    
    String idParam = request.getParameter("id");
    String action = request.getParameter("action"); // 삭제 요청 구분을 위한 파라미터
    
    String title = "";
    String content = "";
    String author = "";
    String filename = "";
    String regDate = "";
    boolean hasPost = false;
    String errorMsg = null;

    // ----------------------------------------------------
    // 🛑 관리자 전용 게시글 삭제 처리 로직
    // ----------------------------------------------------
    if ("delete".equals(action) && idParam != null) {
        // userRole이 null이 아님이 보장되므로 안전하게 비교 가능
        if ("admin".equalsIgnoreCase(userRole)) {
            Connection conn = null;
            PreparedStatement pstmt = null;
            try {
                Class.forName("org.mariadb.jdbc.Driver");
                conn = DriverManager.getConnection("jdbc:mariadb://localhost:3306/vuln_db", "vulnuser", "vulnpass1234");
                
                String deleteSql = "DELETE FROM posts WHERE id = ?";
                pstmt = conn.prepareStatement(deleteSql);
                pstmt.setInt(1, Integer.parseInt(idParam));
                
                int deletedRows = pstmt.executeUpdate();
                if (deletedRows > 0) {
                    out.println("<script>alert('🗑️ 관리자 권한으로 게시글이 삭제되었습니다.'); location.href='search.jsp';</script>");
                    return;
                } else {
                    errorMsg = "삭제할 게시글을 찾을 수 없습니다.";
                }
            } catch (Exception e) {
                errorMsg = "삭제 중 데이터베이스 오류 발생: " + e.getMessage();
            } finally {
                if (pstmt != null) try { pstmt.close(); } catch(Exception e) {}
                if (conn != null) try { conn.close(); } catch(Exception e) {}
            }
        } else {
            out.println("<script>alert('❌ 경고: 권한이 없습니다. 관리자만 삭제할 수 있습니다.'); history.back();</script>");
            return;
        }
    }

    // ----------------------------------------------------
    // 📄 게시글 상세 조회 로직 (누구나 접근 가능)
    // ----------------------------------------------------
    if (idParam != null && !idParam.trim().isEmpty()) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            Class.forName("org.mariadb.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mariadb://localhost:3306/vuln_db", "vulnuser", "vulnpass1234");

            String sql = "SELECT * FROM posts WHERE id = ?";
            pstmt = conn.prepareStatement(sql);
            pstmt.setInt(1, Integer.parseInt(idParam));
            rs = pstmt.executeQuery();

            if (rs.next()) {
                title = rs.getString("title");
                content = rs.getString("content");
                author = rs.getString("author");
                filename = rs.getString("filename");
                regDate = (rs.getTimestamp("reg_date") != null) ? rs.getTimestamp("reg_date").toString() : "";
                hasPost = true;
            } else {
                errorMsg = "존재하지 않는 게시글입니다.";
            }
        } catch (Exception e) {
            errorMsg = "데이터베이스 오류: " + e.getMessage();
        } finally {
            if (rs != null) try { rs.close(); } catch(Exception e) {}
            if (pstmt != null) try { pstmt.close(); } catch(Exception e) {}
            if (conn != null) try { conn.close(); } catch(Exception e) {}
        }
    } else {
        errorMsg = "잘못된 접근입니다. 게시글 ID가 필요합니다.";
    }

    // XSS 방어용 HTML Escaping 처리
    title = replaceHtmlTags(title);
    content = replaceHtmlTags(content);
    author = replaceHtmlTags(author);
%>

<%!
    private String replaceHtmlTags(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;")
                    .replace("/", "&#x2F;");
    }
%>

    <div style="border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
        <h2 style="margin: 0; color: #2c3e50;">📄 게시글 상세보기</h2>
        
        <% if ("admin".equalsIgnoreCase(userRole)) { %>
            <button onclick="confirmDelete(<%= idParam %>);" style="background-color: #e74c3c; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; cursor: pointer;">
                🗑️ 게시글 삭제
            </button>
        <% } %>
    </div>

    <% if (errorMsg != null) { %>
        <div style="background-color: #f8d7da; color: #721c24; padding: 12px; border: 1px solid #f5c6cb; border-radius: 4px; margin-bottom: 1.5rem; font-weight: bold;">
            ⚠️ <%= errorMsg %>
        </div>
    <% } else if (hasPost) { %>
        <div style="background-color: #fff; padding: 25px; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
            <h3 style="margin-top: 0; color: #2c3e50; font-size: 1.5rem;"><%= title %></h3>
            
            <p style="color: #7f8c8d; font-size: 0.9em; margin-bottom: 15px;">
                작성자: <strong><%= author %></strong> | 작성일: <%= regDate %>
            </p>
            
            <hr style="border: 0; border-top: 1px solid #eee; margin-bottom: 20px;">
            
            <div style="min-height: 200px; font-size: 1.05rem; line-height: 1.6; white-space: pre-wrap;"><%= content %></div>

            <% if (filename != null && !filename.isEmpty()) { %>
                <div style="background-color: #f2f6f8; padding: 12px; border-radius: 4px; margin-top: 20px;">
                    <strong>📎 첨부파일 자료 다운로드:</strong> 
                    <a href="download.jsp?filename=<%= replaceHtmlTags(filename) %>" style="color: #2980b9; text-decoration: none; font-weight: bold; margin-left: 5px;">
                        <%= filename %>
                    </a>
                </div>
            <% } %>
        </div>
    <% } %>

    <div style="margin-top: 20px;">
        <a href="search.jsp" style="text-decoration: none; color: #3498db; font-weight: bold;">◀ 목록으로 돌아가기</a>
    </div>

    <script>
        function confirmDelete(postId) {
            if (confirm("정말로 이 게시글을 삭제하시겠습니까? 삭제 후에는 복구할 수 없습니다.")) {
                location.href = "view.jsp?id=" + postId + "&action=delete";
            }
        }
    </script>

<%-- 공통 푸터 포함 --%>
<%@ include file="footer.jsp" %>
