<%@ page contentType="text/html; charset=UTF-8" %>
<%
	String q = request.getParameter("q");
	if (q == null) 
		q = "";
%>

<title>검색 - VulnApp</title>

<%@ include file="header.jsp" %> <h2>게시물 검색 (XSS Test)</h2>
    <form class="search-form" method="GET" action="search.jsp">
        <input type="text" name="q" placeholder="검색어를 입력하세요..." required>
        <button type="submit" class="btn">검색</button>
    </form>

    <% if (!q.isEmpty()) { %>
        <div class="result-area">
            <strong>검색 결과:</strong> <span><%= q %></span> 문서를 찾을 수 없습니다.
        </div>
    <% } %>

<%@ include file="footer.jsp" %>
