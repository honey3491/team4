<%@ page contentType="text/html; charset=UTF-8" %>

<%@ page import="java.sql.*" %>



<%-- 공통 헤더 포함 --%>

<%@ include file="header.jsp" %>



<%

    request.setCharacterEncoding("UTF-8");

   

    // 💡 세션 유실 방어: 세션이 없거나 유저 권한이 없는 경우 안전하게 guest 처리

    // ⭕ 수정된 view.jsp 코드

    // 새로 선언(String)하지 않고, header.jsp가 만든 userRole이 null인지만 체크합니다.

    if (userRole == null) {

        userRole = "guest";

    }

   

    String idParam = request.getParameter("postid");

    String action = request.getParameter("action");

   

    String title = "";

    String content = "";

    String author = "";

    String filename = "";

    String regDate = "";

    boolean hasPost = false;

    String errorMsg = null;



    // 💡 방어 코드 1: postid 파라미터가 비어있거나 숫자가 아닌 경우 예외 처리

    int postId = -1;

    if (idParam != null && !idParam.trim().isEmpty()) {

        try {

            postId = Integer.parseInt(idParam.trim());

        } catch (NumberFormatException nfe) {

            errorMsg = "올바르지 않은 게시글 번호 형식입니다. (전달된 값: " + idParam + ")";

        }

    } else {

        errorMsg = "잘못된 접근입니다. URL에 postid 파라미터가 누락되었습니다. (예: view.jsp?postid=1)";

    }



    // 🛑 [관리자 전용] 게시글 삭제 처리 로직

    if (errorMsg == null && "delete".equals(action) && postId != -1) {

        if ("admin".equalsIgnoreCase(userRole)) {

            Connection conn = null;

            PreparedStatement pstmt = null;

            try {

                Class.forName("org.mariadb.jdbc.Driver");

                conn = DriverManager.getConnection("jdbc:mariadb://mariadb.cinwlvqqoprv.ap-northeast-2.rds.amazonaws.com/vuln_db", "vulnuser", "vulnpass1234");

               

                String deleteSql = "DELETE FROM posts WHERE id = ?";

                pstmt = conn.prepareStatement(deleteSql);

                pstmt.setInt(1, postId);

               

                int deletedRows = pstmt.executeUpdate();

                if (deletedRows > 0) {

                    out.println("<script>alert('🗑️ 관리자 권한으로 게시글이 삭제되었습니다.'); location.href='search.jsp';</script>");

                    return;

                } else {

                    errorMsg = "삭제할 게시글(" + postId + ")을 찾을 수 없습니다.";

                }

            } catch (Exception e) {

                errorMsg = "🔴 [삭제 에러] DB 처리 중 오류 발생: " + e.getMessage();

            } finally {

                if (pstmt != null) try { pstmt.close(); } catch(Exception e) {}

                if (conn != null) try { conn.close(); } catch(Exception e) {}

            }

        } else {

            out.println("<script>alert('❌ 경고: 권한이 없습니다. 관리자만 삭제할 수 있습니다.'); history.back();</script>");

            return;

        }

    }



    // 📄 게시글 상세 조회 로직

    if (errorMsg == null && postId != -1) {

        Connection conn = null;

        PreparedStatement pstmt = null;

        ResultSet rs = null;



        try {

            Class.forName("org.mariadb.jdbc.Driver");

            conn = DriverManager.getConnection("jdbc:mariadb://mariadb.cinwlvqqoprv.ap-northeast-2.rds.amazonaws.com/vuln_db", "vulnuser", "vulnpass1234");



            // 💡 만약 테이블의 기본키 컬럼명이 'id'가 아니라면 이 부분을 수정해야 할 수 있습니다.

            String sql = "SELECT * FROM posts WHERE id = ?";

            pstmt = conn.prepareStatement(sql);

            pstmt.setInt(1, postId);

            rs = pstmt.executeQuery();



            if (rs.next()) {

                // 💡 방어 코드 2: 컬럼 유무 및 Null값 검증 (에러 발생 시 어떤 컬럼이 문제인지 정확히 명시)

                try { title = rs.getString("title"); } catch(Exception e) { title = "[title 컬럼 로드 실패]"; }

                try { content = rs.getString("content"); } catch(Exception e) { content = "[content 컬럼 로드 실패]"; }

                try { author = rs.getString("author"); } catch(Exception e) { author = "[author 컬럼 로드 실패]"; }

                try { filename = rs.getString("filename"); } catch(Exception e) { filename = ""; }

               

                // 날짜 컬럼 예외 처리

                try {

                    Timestamp ts = rs.getTimestamp("reg_date");

                    regDate = (ts != null) ? ts.toString() : "날짜 정보 없음";

                } catch (Exception dateEx) {

                    try {

                        regDate = rs.getString("reg_date"); // 텍스트 형태일 경우 대비

                    } catch(Exception e) {

                        regDate = "날짜 컬럼 로드 실패";

                    }

                }

               

                hasPost = true;

            } else {

                errorMsg = "🔍 데이터베이스에 " + postId + "번 게시글이 존재하지 않습니다.";

            }

        } catch (Exception e) {

            // 💡 중요: 500 에러로 뻗는 대신 화면에 원인을 출력합니다.

            errorMsg = "🔴 [조회 에러] 마리아DB 연동 중 예외 발생: " + e.getMessage();

        } finally {

            if (rs != null) try { rs.close(); } catch(Exception e) {}

            if (pstmt != null) try { pstmt.close(); } catch(Exception e) {}

            if (conn != null) try { conn.close(); } catch(Exception e) {}

        }

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

       

        <% if ("admin".equalsIgnoreCase(userRole) && errorMsg == null && hasPost) { %>

            <button onclick="confirmDelete(<%= postId %>);" style="background-color: #e74c3c; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; cursor: pointer;">

                🗑️ 게시글 삭제

            </button>

        <% } %>

    </div>



    <% if (errorMsg != null) { %>

        <div style="background-color: #f8d7da; color: #721c24; padding: 20px; border: 2px solid #f5c6cb; border-radius: 6px; margin-bottom: 1.5rem;">

            <h4 style="margin-top: 0; color: #c0392b; font-size: 1.15rem;">⚠️ 시스템 내부 연동 오류</h4>

            <p style="font-weight: bold; line-height: 1.5;"><%= errorMsg %></p>

            <p style="font-size: 0.85em; color: #7f8c8d; margin-bottom: 0;">

                💡 <strong>조치 팁:</strong> 만약 'Unknown column' 에러가 뜬다면 데이터베이스 테이블 구조와 소스코드의 컬럼명이 일치하는지 확인하세요.

            </p>

        </div>

    <% } %>



    <% if (hasPost) { %>

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

                    <a href="fileDownload.jsp?filename=<%= replaceHtmlTags(filename) %>" style="color: #2980b9; text-decoration: none; font-weight: bold; margin-left: 5px;">

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

                location.href = "view.jsp?postid=" + postId + "&action=delete";

            }

        }

    </script>



<%-- 공통 푸터 포함 --%>

<%@ include file="footer.jsp" %>
