<%@ page contentType="text/html; charset=UTF-8" %>
<%
    // 1. 현재 브라우저에 연결된 세션을 완전히 파기 (로그아웃 처리)
    // session.setAttribute("userId", ...) 로 저장했던 모든 정보가 날아갑니다.
    session.invalidate();

    // 2. 메인 페이지(index.jsp)로 즉시 이동시킴
    // request.getContextPath()를 사용하면 향후 폴더 이름(vulnapp)이 바뀌어도 안전합니다.
    response.sendRedirect(request.getContextPath() + "/");
%>
