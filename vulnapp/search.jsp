<%@ page contentType="text/html; charset=UTF-8" %>
<%
	String q = request.getParameter("q");
	if (q == null) 
		q = "";
%>
<html>
	<head>
	<title>XSS Test</title>
	</head>
	<body>	
		<h2>XSS Test</h2>

			<form method="GET" action="search.jsp">
			<input type="text"name="q" placeholder="검색어 입력">
			<button type="submit">검색</button>
		</form>

		<hr>
		<p>검색어: <%= q %></p>
	</body>
	
</html>
