<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.io.*, java.net.*" %>

<%-- 공통 헤더 포함 --%>
<%@ include file="header.jsp" %>

<%
    request.setCharacterEncoding("UTF-8");
    String targetUrl = request.getParameter("url");
    
    String responseContent = "";
    String errorMsg = null;

    if (targetUrl != null && !targetUrl.trim().isEmpty()) {
        BufferedReader in = null;
        try {
            // 🚨 취약점 포인트: 사용자가 입력한 URL 주소를 검증 없이 그대로 서버가 대신 커넥션을 맺음
            URL url = new URL(targetUrl.trim());
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            
            // 타임아웃 설정 (3초)
            con.setConnectTimeout(3000);
            con.setReadTimeout(3000);
            con.setRequestMethod("GET");

            // 서버의 응답 코드 확인
            int responseCode = con.getResponseCode();
            
            // 응답 스트림 읽기
            InputStream is = (responseCode == 200) ? con.getInputStream() : con.getErrorStream();
            if (is != null) {
                in = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                String inputLine;
                StringBuilder sb = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    sb.append(inputLine).append("\n");
                }
                responseContent = sb.toString();
            } else {
                responseContent = "응답 본문이 비어있거나 스트림을 열 수 없습니다. (HTTP Status: " + responseCode + ")";
            }

        } catch (Exception e) {
            errorMsg = "서버 간 통신 요류 (SSRF 예외 발생): " + e.getMessage();
        } finally {
            if (in != null) try { in.close(); } catch(Exception e) {}
        }
    } else {
        // 기본 가이드 라인 출력용
        targetUrl = "http://127.0.0.1:8080/vulnapp/internal/secret.jsp";
    }
%>

    <div style="border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; margin-bottom: 20px;">
        <h2 style="margin: 0; color: #d35400;">🌐 원격 데이터 가져오기 (SSRF 취약점 테스터)</h2>
    </div>

    <div style="margin-bottom: 30px; background: #f8f9fa; padding: 20px; border-radius: 8px;">
        <form action="fetch.jsp" method="GET" style="display: flex; gap: 10px; flex-direction: column;">
            <label style="font-weight: bold;">가져올 원격 URL 주소:</label>
            <div style="display: flex; gap: 10px;">
                <input type="text" name="url" value="<%= targetUrl %>" placeholder="http://example.com" 
                       style="flex-grow: 1; padding: 10px; border: 1px solid #ccc; border-radius: 4px;">
                <button type="submit" style="background: #e67e22; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    요청 전송
                </button>
            </div>
        </form>
    </div>

    <h3 style="margin-bottom: 10px;">📊 서버가 받아온 원격지 응답 결과</h3>
    <div style="background-color: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 6px; font-family: monospace; min-height: 150px; white-space: pre-wrap;">
        <% if (errorMsg != null) { %>
            <span style="color: #e74c3c; font-weight: bold;"><%= errorMsg %></span>
        <% } else if (!responseContent.isEmpty()) { %>
            <%-- 스캐너 진단 및 스크립트 실행 방지를 위한 안전한 일반 텍스트 출력 --%>
            <%= responseContent.replace("<", "&lt;").replace(">", "&gt;") %>
        <% } else { %>
            <span style="color: #7f8c8d;">URL을 입력하고 요청 전송 버튼을 누르면 서버가 받아온 원격 데이터 결과가 여기에 표시됩니다.</span>
        <% } %>
    </div>

<%@ include file="footer.jsp" %>
