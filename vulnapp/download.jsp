<%@ page import="java.io.*, java.nio.file.Files, java.util.Base64" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<%
    String fileName = request.getParameter("filename");
    String savePath = "/opt/tomcat/webapps/vulnapp/backup/"; 
    
    String fileContent = "";
    String base64Image = "";
    boolean isImage = false;

    if (fileName != null && !fileName.trim().isEmpty()) {
        
        // 🚨 취약점 포인트: 경로 조작("../") 검증 로직 누락
        File f = new File(savePath + fileName);

        if (f.exists() && f.isFile()) {
            try {
                String lowerName = fileName.toLowerCase();
                
                // 1. 이미지 파일인 경우 (확장자 체크)
                if (lowerName.endsWith(".jpg") || lowerName.endsWith(".jpeg") || lowerName.endsWith(".png") || lowerName.endsWith(".gif")) {
                    isImage = true;
                    // 파일을 바이트 배열로 읽어 Base64 문자열로 인코딩 (브라우저가 바로 이미지를 그릴 수 있게 함)
                    byte[] fileBytes = Files.readAllBytes(f.toPath());
                    base64Image = Base64.getEncoder().encodeToString(fileBytes);
                } 
                // 2. 텍스트 파일인 경우
                else {
                    BufferedReader br = new BufferedReader(new FileReader(f));
                    String line;
                    StringBuilder sb = new StringBuilder();
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    br.close();
                    fileContent = sb.toString();
                }
            } catch (Exception e) {
                fileContent = "파일을 읽는 중 오류가 발생했습니다: " + e.getMessage();
                isImage = false;
            }
        } else {
            fileContent = "존재하지 않는 파일이거나 접근할 수 없습니다.";
        }
    }
%>

<html>
<head>
    <title>File Viewer (Arbitrary File Read Test)</title>
    <style>
        .content-box {
            background-color: #1e1e1e;
            color: #00ff00;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            max-width: 800px;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .image-box {
            background-color: #f4f4f4;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            max-width: 800px;
            text-align: center;
        }
        .image-box img {
            max-width: 100%;
            height: auto;
        }
    </style>
</head>
<body>
    <h2>자료실 (File Viewer)</h2>
    <hr>
    <p>서버에 저장된 백업 데이터 및 이미지를 확인합니다.</p>
    
    <form action="download.jsp" method="GET">
        <table border="1" cellspacing="0" cellpadding="8" style="text-align: center;">
            <tr>
                <th>선택</th>
                <th>파일명</th>
            </tr>
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
            <tr>
                <td colspan="2">조회 가능한 파일이 없습니다.</td>
            </tr>
            <%
                }
            %>
        </table>
        <br>
        <button type="submit">내용 보기</button>
    </form>
    
    <% if (fileName != null) { %>
        <hr>
        <h3>[ 파일 내용: <%= fileName %> ]</h3>
        
        <% if (isImage && !base64Image.isEmpty()) { %>
            <div class="image-box">
                <img src="data:image/jpeg;base64,<%= base64Image %>" alt="업로드된 이미지">
            </div>
        <% } else { %>
            <div class="content-box"><%= fileContent.replace("<", "&lt;").replace(">", "&gt;") %></div>
        <% } %>
    <% } %>

    <br>
    <a href="javascript:history.back()">[ 이전 페이지로 돌아가기 ]</a>
</body>
</html>
