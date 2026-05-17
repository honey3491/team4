<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" isErrorPage="true" %>
<%
    Integer statusCode = (Integer) request.getAttribute("javax.servlet.error.status_code");
    String requestUri = (String) request.getAttribute("javax.servlet.error.request_uri");

    if (statusCode == null) {
        statusCode = Integer.valueOf(500);
    }
    if (requestUri == null || requestUri.trim().isEmpty()) {
        requestUri = request.getRequestURI();
    }
%>
<%@ include file="header.jsp" %>

    <section class="command-hero">
        <div class="command-hero-main">
            <span class="board-badge">Service Error</span>
            <h2>요청을 처리하지 못했습니다</h2>
            <p>일시적인 오류가 발생했습니다. 잠시 후 다시 시도해 주세요. 문제가 계속되면 운영 담당자에게 문의해 주세요.</p>
        </div>
        <aside class="command-hero-side">
            <div class="command-hero-side-label">Status</div>
            <strong>HTTP <%= statusCode %></strong>
            <p><%= requestUri %> 요청 처리 중 오류가 발생했습니다.</p>
        </aside>
    </section>

    <section class="command-guidance">
        <h3>다음 단계</h3>
        <ul>
            <li>입력값이나 접근 경로를 다시 확인한 뒤 재시도해 주세요.</li>
            <li>동일한 오류가 반복되면 서버 로그와 애플리케이션 설정을 점검해 주세요.</li>
            <li>메인 페이지로 돌아가 다른 기능은 정상 동작하는지 확인할 수 있습니다.</li>
        </ul>
    </section>

    <div class="board-form-panel command-panel">
        <div class="board-panel-heading">
            <h3>바로가기</h3>
            <p>필요한 페이지로 이동해 작업을 계속할 수 있습니다.</p>
        </div>
        <div class="command-code-list">
            <span><a href="<%= request.getContextPath() %>/">메인 페이지</a></span>
            <span><a href="<%= request.getContextPath() %>/board.jsp">안전 게시판</a></span>
            <span><a href="<%= request.getContextPath() %>/command.jsp">운영 상태 센터</a></span>
        </div>
    </div>

<%@ include file="footer.jsp" %>

