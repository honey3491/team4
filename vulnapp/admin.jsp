<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="java.sql.*" %>

<%@ include file="header.jsp" %>
<%    
    // 🚨 취약점 포인트: 로그인을 안 한 사람만 막고, '일반 사용자'인지 '관리자'인지 역할(role)을 검증하지 않음!
    if (userId == null) {
        // 비로그인 사용자는 튕겨냄
        response.sendRedirect("login.jsp");
        return;
    }

    // 2. DB에서 모든 사용자 정보 가져오기
    Connection conn = null;
    Statement stmt = null;
    ResultSet rs = null;
    boolean dbError = false;
    String errMsg = "";

    try {
        Class.forName("org.mariadb.jdbc.Driver");
        conn = DriverManager.getConnection("jdbc:mariadb://localhost:3306/vuln_db", "vulnuser", "vulnpass1234");
        stmt = conn.createStatement();

        // 모든 회원의 정보를 조회
        String sql = "SELECT id, username, password, role FROM users ORDER BY id ASC";
        rs = stmt.executeQuery(sql);
        
    } catch (Exception e) {
        dbError = true;
        errMsg = e.getMessage();
    }
%>
    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; margin-bottom: 20px;">
        <h2 style="margin: 0; color: #8e44ad;">⚙️ 시스템 관리자 대시보드</h2>
        <span style="background-color: #e74c3c; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold;">
            Admin Only
        </span>
    </div>

    <p style="margin-bottom: 1.5rem; color: #7f8c8d;">
        현재 서버에 가입된 모든 회원의 계정 및 권한 정보를 관리합니다. <br>
        <strong style="color: #c0392b;">(경고: 본 페이지는 외부 노출이 엄격히 금지되어 있습니다.)</strong>
    </p>

    <% if (dbError) { %>
        <div style="background-color: #f8d7da; color: #721c24; padding: 12px; border: 1px solid #f5c6cb; border-radius: 4px; margin-bottom: 1.5rem;">
            ⚠️ DB 조회 중 오류가 발생했습니다: <%= errMsg %>
        </div>
    <% } else { %>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; text-align: left;">
            <thead>
                <tr style="background-color: #f2f6f8; border-bottom: 2px solid #bdc3c7;">
                    <th style="padding: 12px; border: 1px solid #ecf0f1;">회원 번호(PK)</th>
                    <th style="padding: 12px; border: 1px solid #ecf0f1;">사용자 ID</th>
                    <th style="padding: 12px; border: 1px solid #ecf0f1;">비밀번호 (평문 노출)</th>
                    <th style="padding: 12px; border: 1px solid #ecf0f1;">권한 (Role)</th>
                    <th style="padding: 12px; border: 1px solid #ecf0f1;">관리</th>
                </tr>
            </thead>
            <tbody>
                <% 
                    if (rs != null) {
                        while (rs.next()) { 
                            String rId = rs.getString("id");
                            String rName = rs.getString("username");
                            String rPw = rs.getString("password");
                            String rRole = rs.getString("role");
                %>
                <tr style="border-bottom: 1px solid #ecf0f1;">
                    <td style="padding: 10px; border: 1px solid #ecf0f1; text-align: center;"><strong><%= rId %></strong></td>
                    <td style="padding: 10px; border: 1px solid #ecf0f1;"><%= rName %></td>
                    <td style="padding: 10px; border: 1px solid #ecf0f1; font-family: monospace; color: #c0392b;"><%= rPw %></td>
                    <td style="padding: 10px; border: 1px solid #ecf0f1; text-align: center;">
                        <% if ("admin".equalsIgnoreCase(rRole)) { %>
                            <span style="color: white; background-color: #e74c3c; padding: 2px 6px; border-radius: 4px; font-size: 0.85em;">Admin</span>
                        <% } else { %>
                            <span style="color: white; background-color: #95a5a6; padding: 2px 6px; border-radius: 4px; font-size: 0.85em;">User</span>
                        <% } %>
                    </td>
                    <td style="padding: 10px; border: 1px solid #ecf0f1; text-align: center;">
                        <button style="background-color: #3498db; color: white; border: none; padding: 4px 8px; border-radius: 3px; cursor: pointer; font-size: 0.85em;">수정</button>
                    </td>
                </tr>
                <% 
                        }
                    } 
                %>
            </tbody>
        </table>
    <% } %>

<%
    // 자원 반납
    try { if (rs != null) rs.close(); } catch(Exception e) {}
    try { if (stmt != null) stmt.close(); } catch(Exception e) {}
    try { if (conn != null) conn.close(); } catch(Exception e) {}
%>

<%@ include file="footer.jsp" %>
