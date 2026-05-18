<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.DriverManager" %>
<%@ page import="java.sql.PreparedStatement" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.sql.Statement" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>

<%!
    private String normalize(String value, int maxLength) {
        if (value == null) {
            return "";
        }

        String trimmed = value.trim().replace("\r\n", "\n").replace('\r', '\n');
        StringBuilder cleaned = new StringBuilder();

        for (int i = 0; i < trimmed.length(); i++) {
            char ch = trimmed.charAt(i);
            if (ch == '\n' || ch == '\t' || ch >= 0x20) {
                cleaned.append(ch);
            }
        }

        if (cleaned.length() > maxLength) {
            return cleaned.substring(0, maxLength);
        }

        return cleaned.toString();
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }

        StringBuilder escaped = new StringBuilder();

        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);

            switch (ch) {
                case '&':
                    escaped.append("&amp;");
                    break;
                case '<':
                    escaped.append("&lt;");
                    break;
                case '>':
                    escaped.append("&gt;");
                    break;
                case '"':
                    escaped.append("&quot;");
                    break;
                case '\'':
                    escaped.append("&#x27;");
                    break;
                case '/':
                    escaped.append("&#x2F;");
                    break;
                default:
                    escaped.append(ch);
            }
        }

        return escaped.toString();
    }
%>

<%
    request.setCharacterEncoding("UTF-8");

    response.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    );

    String currentUserId = (String) session.getAttribute("userId");
    String sessionAuthor = currentUserId == null ? "" : normalize(currentUserId, 40);

    String formTitle = "";
    String formContent = "";
    String errorMessage = "";
    boolean created = "1".equals(request.getParameter("created"));

    List posts = new ArrayList();
    int postCount = 0;

    Connection conn = null;
    Statement stmt = null;
    PreparedStatement insertStmt = null;
    PreparedStatement listStmt = null;
    ResultSet rs = null;

    try {
        Class.forName("org.mariadb.jdbc.Driver");
        conn = DriverManager.getConnection(
            "jdbc:mariadb://mariadb.cinwlvqqoprv.ap-northeast-2.rds.amazonaws.com/vuln_db",
            "vulnuser",
            "vulnpass1234"
        );

        stmt = conn.createStatement();
        stmt.executeUpdate(
            "CREATE TABLE IF NOT EXISTS board_posts (" +
            "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, " +
            "author VARCHAR(40) NOT NULL, " +
            "title VARCHAR(120) NOT NULL, " +
            "content TEXT NOT NULL, " +
            "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );

        if ("POST".equalsIgnoreCase(request.getMethod())) {
            formTitle = normalize(request.getParameter("title"), 120);
            formContent = normalize(request.getParameter("content"), 5000);

            if (sessionAuthor.isEmpty()) {
                errorMessage = "게시글 작성은 로그인 후 이용할 수 있습니다.";
            } else if (formTitle.isEmpty() || formContent.isEmpty()) {
                errorMessage = "제목과 내용을 모두 입력해야 합니다.";
            } else {
                insertStmt = conn.prepareStatement(
                    "INSERT INTO board_posts (author, title, content) VALUES (?, ?, ?)"
                );
                insertStmt.setString(1, sessionAuthor);
                insertStmt.setString(2, formTitle);
                insertStmt.setString(3, formContent);
                insertStmt.executeUpdate();

                response.sendRedirect("board.jsp?created=1");
                return;
            }
        }

        listStmt = conn.prepareStatement(
            "SELECT id, author, title, content, " +
            "DATE_FORMAT(created_at, '%Y-%m-%d') AS created_at " +
            "FROM board_posts ORDER BY id DESC"
        );

        rs = listStmt.executeQuery();

        while (rs.next()) {
            Map post = new HashMap();
            post.put("id", rs.getString("id"));
            post.put("author", rs.getString("author"));
            post.put("title", rs.getString("title"));
            post.put("content", rs.getString("content"));
            post.put("createdAt", rs.getString("created_at"));
            posts.add(post);
        }

        postCount = posts.size();

    } catch (Exception e) {
        errorMessage = "게시판 데이터를 불러오는 중 오류가 발생했습니다: " + e.getMessage();
    } finally {
        try { if (rs != null) rs.close(); } catch (Exception e) {}
        try { if (listStmt != null) listStmt.close(); } catch (Exception e) {}
        try { if (insertStmt != null) insertStmt.close(); } catch (Exception e) {}
        try { if (stmt != null) stmt.close(); } catch (Exception e) {}
        try { if (conn != null) conn.close(); } catch (Exception e) {}
    }

    String authorDisplay = sessionAuthor.isEmpty() ? "로그인 필요" : sessionAuthor;
%>

<%@ include file="header.jsp" %>

<section class="board-hero">
    <div class="board-hero-copy">
        <span class="board-badge">Stored XSS Protected</span>
        <h2>안전한 게시판</h2>
        <p>입력값은 서버에서 정규화하고, 출력 시 HTML 이스케이프를 적용합니다.</p>
    </div>

    <div class="board-hero-stat">
        <strong><%= postCount %></strong>
        <span>누적 게시글</span>
    </div>
</section>

<% if (created) { %>
    <div class="result-area board-success">
        게시글이 등록되었습니다.
    </div>
<% } %>

<% if (!errorMessage.isEmpty()) { %>
    <div class="result-area board-error">
        <%= escapeHtml(errorMessage) %>
    </div>
<% } %>

<div class="board-layout">
    <section class="board-form-panel">
        <div class="board-panel-heading">
            <h3>새 글 작성</h3>
            <p>작성한 내용은 안전한 텍스트로 저장 및 출력됩니다.</p>
        </div>

        <form action="board.jsp" method="post" class="board-form" autocomplete="off">
            <label for="author">작성자</label>
            <input
                type="text"
                id="author"
                name="author_display"
                maxlength="40"
                readonly
                placeholder="로그인 후 자동 입력됩니다"
                value="<%= escapeHtml(authorDisplay) %>"
            >

            <label for="title">제목</label>
            <input
                type="text"
                id="title"
                name="title"
                maxlength="120"
                required
                placeholder="제목을 입력하세요"
                value="<%= escapeHtml(formTitle) %>"
            >

            <label for="content">내용</label>
            <textarea
                id="content"
                name="content"
                rows="6"
                maxlength="5000"
                required
                placeholder="내용을 입력하세요"
            ><%= escapeHtml(formContent) %></textarea>

            <button type="submit" class="btn">등록하기</button>
        </form>
    </section>

    <section class="board-list-panel">
        <div class="board-list-header">
            <h3>게시글 목록</h3>
            <span><%= postCount %>건</span>
        </div>

        <% if (posts.isEmpty()) { %>
            <div class="board-empty">첫 게시글을 작성해 보세요.</div>
        <% } else { %>
            <div class="board-post-list">
                <%
                    for (int i = 0; i < posts.size(); i++) {
                        Map post = (Map) posts.get(i);
                %>
                    <article class="board-post-card">
                        <div class="board-post-meta">
                            <span class="board-post-id">
                                #<%= escapeHtml((String) post.get("id")) %>
                            </span>

                            <strong class="board-post-title">
                                <%= escapeHtml((String) post.get("title")) %>
                            </strong>

                            <span class="board-post-author">
                                <%= escapeHtml((String) post.get("author")) %>
                            </span>

                            <span class="board-post-date">
                                <%= escapeHtml((String) post.get("createdAt")) %>
                            </span>
                        </div>

                        <div class="board-post-content">
                            <%= escapeHtml((String) post.get("content")) %>
                        </div>
                    </article>
                <%
                    }
                %>
            </div>
        <% } %>
    </section>
</div>

<%@ include file="footer.jsp" %>
