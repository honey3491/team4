<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.io.*, java.util.*, java.sql.*" %>
<%@ page import="javax.servlet.http.Part" %>

<%-- 💡 공통 헤더 포함 --%>
<%@ include file="header.jsp" %>

<%
    request.setCharacterEncoding("UTF-8"); // 한글 깨짐 방지

    // 1. 저장 경로 설정
    String savePath = request.getServletContext().getRealPath("/uploads");
    File uploadDir = new File(savePath);
    if (!uploadDir.exists()) uploadDir.mkdirs();

    // 2. 💡 중요: multipart/form-data에서 텍스트 데이터 읽기
    // 일반 request.getParameter가 작동하지 않을 경우를 대비해 Part에서 직접 읽습니다.
    String title = "";
    String content = "";
    
    // 제목(title) 읽기
    Part titlePart = request.getPart("title");
    if (titlePart != null) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(titlePart.getInputStream(), "UTF-8"));
        title = reader.readLine();
    }

    // 내용(content) 읽기
    Part contentPart = request.getPart("content");
    if (contentPart != null) {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(contentPart.getInputStream(), "UTF-8"));
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        content = sb.toString();
    }

    // 3. 파일 데이터 처리
    Part filePart = request.getPart("uploadFile");
    String fileName = "";
    if (filePart != null && filePart.getSize() > 0) {
        String contentDisp = filePart.getHeader("content-disposition");
        for (String cd : contentDisp.split(";")) {
            if (cd.trim().startsWith("filename")) {
                fileName = cd.substring(cd.indexOf("=") + 2, cd.length() - 1);
            }
        }
        if (!fileName.isEmpty()) {
            filePart.write(savePath + File.separator + fileName);
        }
    }

    // 4. DB 저장
    Connection conn = null;
    PreparedStatement pstmt = null;

    try {
        Class.forName("org.mariadb.jdbc.Driver");
        conn = DriverManager.getConnection(
            "jdbc:mariadb://mariadb.cinwlvqqoprv.ap-northeast-2.rds.amazonaws.com:3306/vuln_db", 
            "vulnuser", 
            "vulnpass1234"
        );

        String sql = "INSERT INTO posts (title, content, filename, author) VALUES (?, ?, ?, ?)";
        pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, title);
        pstmt.setString(2, content);
        pstmt.setString(3, fileName);
        pstmt.setString(4, userId); // header.jsp의 변수

        pstmt.executeUpdate();
%>
    <div style="border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; margin-bottom: 20px;">
        <h2 style="margin: 0; color: #27ae60;">🎉 포스트 등록 완료!</h2>
    </div>
    <div style="background-color: #fff; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
        <h3><%= title %></h3>
        <p>작성자: <%= userId %></p>
        <hr>
        <div><%= content %></div>
    </div>
<%
    } catch (Exception e) {
        out.println("❌ DB 오류: " + e.getMessage());
    } finally {
        if (pstmt != null) try { pstmt.close(); } catch(Exception e) {}
        if (conn != null) try { conn.close(); } catch(Exception e) {}
    }
%>

<%@ include file="footer.jsp" %>
