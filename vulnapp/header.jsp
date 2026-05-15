<%@ page pageEncoding="UTF-8" %>
<%
    // 💡 1. 세션에서 사용자 정보(예: userId)를 가져와 로그인 여부를 확인합니다.
    String userId = (String) session.getAttribute("userId");
    String userNo = (String) session.getAttribute("userNo");
    boolean isLoggedIn = (userId != null);
%>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="logo" href="index.jsp">
		<a href="<%= request.getContextPath() %>/" style="text-decoration: none; color: inherit;">
			🛡️ VulnApp
		</a>
	</div>
        <ul class="nav-links">
            <li><a href="search.jsp">통합 검색</a></li>
            <li><a href="download.jsp">자료실</a></li>
            
            <% if (isLoggedIn) { %>
                <li><a href="profile.jsp?user_idx=<%= userNo %>">프로필 (<%= userId %>)</a></li>
                <li><a href="logout.jsp">로그아웃</a></li>
            <% } else { %>
                <li><a href="login.jsp">로그인</a></li>
            <% } %>
        </ul>
    </nav>
    <main class="container">
        <div class="card">
