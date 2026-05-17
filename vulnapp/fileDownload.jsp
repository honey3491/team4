<%@ page contentType="application/octet-stream; charset=UTF-8" %>
<%@ page import="java.io.*, java.net.URLEncoder" %>
<%
    request.setCharacterEncoding("UTF-8");
    String filename = request.getParameter("filename");

    if (filename != null && !filename.trim().isEmpty()) {
        // 💡 실제 물리 파일들이 위치한 서버 내부 경로
        String uploadDir = "/opt/tomcat/webapps/vulnapp/uploads/"; 
        File file = new File(uploadDir, filename);

        // 🚨 취약점 포인트 (Path Traversal): 
        // 입력값에 ../ 같은 상위 디렉토리 이동 문태를 필터링하지 않아, 
        // 공격자가 임의의 시스템 파일(예: ../../../../etc/passwd)을 가로챌 수 있습니다.
        if (file.exists() && file.isFile()) {
            
            // 브라우저가 다운로드 창을 켜도록 헤더 정의
            String encodedName = URLEncoder.encode(file.getName(), "UTF-8").replaceAll("\\+", "%20");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + encodedName + "\"");
            
            // 톰캣 자체의 Output 스트림 중복 서블릿 에러 방지
            out.clear();
            pageContext.pushBody();
            
            FileInputStream fis = null;
            OutputStream os = null;
            try {
                fis = new FileInputStream(file);
                os = response.getOutputStream();
                
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
                os.flush();
            } catch (Exception e) {
                // 다운로드 중 에러 발생 시 처리
            } finally {
                if (fis != null) try { fis.close(); } catch(Exception e) {}
            }
            return;
        } else {
            // 파일이 없을 경우 경고 후 뒤로가기
            response.setContentType("text/html;charset=UTF-8");
            out.println("<script>alert('❌ [파일 에러] 요청하신 파일을 서버 스토리지에서 찾을 수 없습니다.'); history.back();</script>");
        }
    } else {
        response.setContentType("text/html;charset=UTF-8");
        out.println("<script>alert('잘못된 접근입니다.'); history.back();</script>");
    }
%>
