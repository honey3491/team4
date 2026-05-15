<%@ page import="java.io.*" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<%
    String fileName = request.getParameter("filename");
    // 💡 웹에서 접근 가능한 경로로 설정 (취약점 포인트)
    String relativePath = "backup/" + fileName; 
    String fullPath = "/opt/tomcat/webapps/vulnapp/backup/" + fileName;
    
    boolean isImage = false;
    if (fileName != null) {
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".jpg") || lower.endsWith(".png") || lower.endsWith(".gif") || lower.endsWith(".jpeg")) {
            isImage = true;
        }
    }
%>

<html>
<head><title>File Viewer</title></head>
<body>
    <h2>자료실 (Simple Viewer)</h2>
    
    <form action="download.jsp" method="GET">
        <select name="filename">
            <option value="resized-수달.jpg">수달 사진</option>
            <option value="memo.txt">메모 파일</option>
        </select>
        <button type="submit">확인</button>
    </form>

    <hr>

    <% if (fileName != null) { %>
        <h3>조회 파일: <%= fileName %></h3>
        
        <% if (isImage) { %>
            <div style="border: 1px solid #ccc;">
                <img src="backup/<%= fileName %>" style="max-width: 500px;">
            </div>
            <p>경로: backup/<%= fileName %></p>
        <% } else { %>
            <pre style="background: #eee; padding: 10px;">
<%
    try {
        BufferedReader br = new BufferedReader(new FileReader(fullPath));
        String line;
        while ((line = br.readLine()) != null) {
            out.println(line);
        }
        br.close();
    } catch (Exception e) {
        out.println("파일을 읽을 수 없습니다.");
    }
%>
            </pre>
        <% } %>
    <% } %>
</body>
</html>
