<%@ page import="java.io.*, java.nio.file.Files, java.util.Base64" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<%
    String fileName = request.getParameter("filename");
    String savePath = "/opt/tomcat/webapps/vulnapp/backup/"; 
    
    String fileContent = "";
    String base64Image = "";
    String mimeType = "";
    boolean isImage = false;

    if (fileName != null && !fileName.trim().isEmpty()) {
        // 파일명 앞뒤 공백 제거
        fileName = fileName.trim();
        File f = new File(savePath + fileName);

        if (f.exists() && f.isFile()) {
            try {
                String lowerName = fileName.toLowerCase();
                
                // 1. 지원하는 이미지 확장자 체크 (.jpg, .jpeg, .png, .gif)
                if (lowerName.endsWith(".jpg") || lowerName.endsWith(".jpeg") || 
                    lowerName.endsWith(".png") || lowerName.endsWith(".gif")) {
                    
                    isImage = true;
                    
                    // MIME 타입 설정
                    if (lowerName.endsWith(".png")) mimeType = "image/png";
                    else if (lowerName.endsWith(".gif")) mimeType = "image/gif";
                    else mimeType = "image/jpeg"; // jpg, jpeg

                    // 파일을 바이트 배열로 읽어 Base64로 인코딩
                    byte[] fileBytes = Files.readAllBytes(f.toPath());
                    base64Image = Base64.getEncoder().encodeToString(fileBytes);
                } 
                // 2. 텍스트 파일 처리
                else {
                    BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8"));
                    String line;
                    StringBuilder sb = new StringBuilder();
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    br.close();
                    fileContent = sb.toString();
                }
            } catch (Exception e) {
                isImage = false;
                fileContent = "파일 처리 중 에러 발생: " + e.getMessage();
            }
        } else {
            fileContent = "파일을 찾을 수 없습니다: " + f.getAbsolutePath();
        }
    }
%>

<html>
<head>
    <title>File Viewer (Vulnerable App)</title>
    <style>
        .content-box { background-color: #1e1e1e; color: #00ff00; padding: 15px; border-radius: 5px; font-family: monospace; white-space: pre-wrap; word-wrap: break-word; }
        .image-box { background-color: #fff; padding: 10px; border: 2px solid #ccc; text-align: center; }
        .image-box img { max-width: 100%; height: auto; box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
        .error-text { color: #ff4444; font-weight: bold; }
    </style>
</head>
<body>
    <h2>자료실 (File Viewer)</h2>
    <hr>
    
    <form action="download.jsp" method="GET">
        <table border="1" cellpadding="10" style="border-collapse: collapse;">
            <tr bgcolor="#eeeeee"><th>선택</th><th>파일명</th></tr>
            <%
                File dir = new File(savePath);
                File[] files = dir.listFiles();
                if (files != null && files.length > 0) {
                    for (File file : files) {
                        if (file.isFile()) {
            %>
            <tr>
                <td><input type="radio" name="filename" value="<%= file.getName() %>" required></td>
                <td><%= file.getName() %></td>
            </tr>
            <% 
                        }
                    }
                } else {
            %>
            <tr><td colspan="2">파일이 없습니다. (경로: <%= savePath %>)</td></tr>
            <% } %>
        </table><br>
        <button type="submit">내용 보기</button>
    </form>
    
    <% if (fileName != null) { %>
        <hr>
        <h3>조회된 파일: <%= fileName %></h3>
        
        <% if (isImage && !base64Image.isEmpty()) { %>
            <div class="image-box">
                <img src="data:<%= mimeType %>;base64,1<%= base64Image %>" alt="Image Content">
            </div>
        <% } else if (isImage && base64Image.isEmpty()) { %>
            <p class="error-text">이미지 데이터를 인코딩하지 못했습니다.</p>
        <% } else { %>
            <div class="content-box"><%= fileContent.replace("<", "&lt;").replace(">", "&gt;") %></div>
        <% } %>
    <% } %>
    <br>
    <a href="javascript:history.back()">[ 돌아가기 ]</a>
</body>
</html>
