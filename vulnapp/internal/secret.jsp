<%@ page contentType="text/html; charset=UTF-8" %>
<%
    // 💡 Nginx 프록시 환경에서 실제 사용자의 원격 IP를 가져오는 올바른 방법
    String remoteAddr = request.getHeader("X-Real-IP");
    
    // 만약 Nginx를 거치지 않고 직접 접속했거나 헤더가 없다면 기본 메서드 사용
    if (remoteAddr == null || remoteAddr.isEmpty()) {
        remoteAddr = request.getRemoteAddr();
    }
    
    // 테스트용 확인 콘솔 (서버 로그에서 확인 가능)
    System.out.println("[SSRF Test] Detected Remote IP: " + remoteAddr);

    // 🛡️ 오직 내부 루프백 주소(Nginx의 내부 토스 포함)일 때만 기밀 출력
    // 외부에서 접속하면 X-Real-IP에 사용자의 실제 공인 IP가 담기므로 이 조건문을 통과할 수 없습니다.
    if ("127.0.0.1".equals(remoteAddr) || "0:0:0:0:0:0:0:1".equals(remoteAddr) || "::1".equals(remoteAddr)) {
%>
        INTERNAL_SECRET_TEST: [FLAG_SSRF_SUCCESS_2026] - 이 데이터는 서버 내부망에서만 조회할 수 있는 일급 기밀 정보입니다.
<%
    } else {
        // 외부 사용자가 직접 브라우저로 들어오면 확실하게 차단
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
%>
        <div style="padding:20px; border:2px solid #e74c3c; background:#fdf2f2; border-radius:8px; font-family:sans-serif;">
            <h3 style="color:#c0392b; margin-top:0;">❌ Access Denied (403 Forbidden)</h3>
            <p>외부망에서의 직접적인 접근은 보안 정책에 의해 엄격히 금지됩니다.</p>
            <p style="font-size:0.9em; color:#7f8c8d;">당신의 실제 탐지된 IP: <strong><%= remoteAddr %></strong></p>
            <p style="font-size:0.85em; color:#95a5a6; background:#fff; padding:5px; border:1px dashed #ccc;">
                💡 <strong>힌트:</strong> 이 정보는 서버 내부에서만 호출되어야 합니다. <code>fetch.jsp</code> 취약점을 이용해 서버가 자신에게 요청하도록 유도하세요.
            </p>
        </div>
<%
    }
%>
