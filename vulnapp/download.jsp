<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.io.*" %>

<%-- 💡 공통 헤더 포함 --%>
<%@ include file="header.jsp" %>

<%
    String fileName = request.getParameter("filename");
    
    // 🚨 취약점 포인트: 사용자가 입력한 파일 이름을 필터링(../ 차단 등) 없이 경로에 그대로 병합
    String fullPath = "/opt/tomcat/webapps/vulnapp/backup/" + fileName;
    
    // 이미지 파일 여부 확인
    boolean isImage = false;
    if (fileName != null) {
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".jpg") || lower.endsWith(".png") || lower.endsWith(".gif") || lower.endsWith(".jpeg")) {
            isImage = true;
        }
    }
%>

    <div style="border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; margin-bottom: 20px;">
        <h2 style="margin: 0; color: #c0392b;">💾 자료실 (Path Traversal Test)</h2>
    </div>

    <p style="margin-bottom: 1.5rem; color: #7f8c8d;">
        서버에 보관된 백업 이미지 파일들을 열람하는 페이지입니다.<br>
        <strong>(힌트: 드롭다운을 조작하거나 URL 파라미터를 변경하여 숨겨진 서버 파일을 읽어보세요.)</strong>
    </p>

    <div style="background-color: #f9f9f9; padding: 15px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">
        <form action="download.jsp" method="GET" style="margin: 0; display: flex; gap: 10px; align-items: center;">
            <label for="filename" style="font-weight: bold;">파일 선택:</label>
            <select name="filename" id="filename" style="padding: 8px; border-radius: 4px; border: 1px solid #ccc; flex-grow: 1;">
                <option value="수달.jpg" <%= "수달.jpg".equals(fileName) ? "selected" : "" %>>수달 사진</option>
                <option value="마눌.jpg" <%= "마눌.jpg".equals(fileName) ? "selected" : "" %>>마눌고양이 사진</option>
                <option value="람쥐.jpg" <%= "람쥐.jpg".equals(fileName) ? "selected" : "" %>>다람쥐 사진</option>
            </select>
            <button type="submit" style="background-color: #2c3e50; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer;">
                열람하기
            </button>
        </form>
    </div>

    <% if (fileName != null) { %>
        <h3 style="color: #2980b9; margin-bottom: 10px;">📄 조회 결과: <%= fileName %></h3>
        
        <% if (isImage) { %>
            <div style="border: 1px solid #ccc; padding: 10px; text-align: center; background-color: #fff; border-radius: 5px;">
                <img src="backup/<%= fileName %>" style="max-width: 100%; max-height: 400px; border-radius: 4px;">
            </div>
            <p style="color: #95a5a6; font-size: 0.9em; margin-top: 10px;">
                실제 로드 경로: <code>backup/<%= fileName %></code>
            </p>
        <% } else { %>
            <div style="background-color: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto;">
                <pre style="margin: 0; font-family: 'Courier New', Courier, monospace; font-size: 0.9em;"><%
    try {
        BufferedReader br = new BufferedReader(new FileReader(fullPath));
        String line;
        while ((line = br.readLine()) != null) {
            // HTML 태그가 해석되지 않고 글자 그대로 보이게 치환하여 파일 원본 구조를 유지
            out.println(line.replace("<", "&lt;").replace(">", "&gt;"));
        }
        br.close();
    } catch (Exception e) {
        out.println("❌ 파일을 읽을 수 없습니다: " + e.getMessage());
    }
%></pre>
            </div>
        <% } %>
    <% } %>

<%-- 💡 공통 푸터 포함 --%>
<%@ include file="footer.jsp" %>
