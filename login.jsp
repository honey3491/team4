<%@ page import="java.sql.*" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<%
String id = request.getParameter("id");
String pw = request.getParameter("pw");

String result = "";

if (id != null && pw != null) {
    Connection conn = null;
    Statement stmt = null;
    ResultSet rs = null;

    try {
        Class.forName("org.mariadb.jdbc.Driver");
        conn = DriverManager.getConnection(
            "jdbc:mariadb://localhost:3306/vuln_db",
            "vulnuser",
            "vulnpass1234"
        );

        stmt = conn.createStatement();

        // 실습용 취약 코드: PreparedStatement를 쓰지 않음
        String sql = "SELECT * FROM users WHERE username='" + id + "' AND password='" + pw + "'";

        rs = stmt.executeQuery(sql);

        if (rs.next()) {
            result = "Login Success - Welcome " + rs.getString("username") + " / role=" + rs.getString("role");
        } else {
            result = "Login Failed";
        }

    } catch (Exception e) {
        result = "Error: " + e.getMessage();
    } finally {
        try { if (rs != null) rs.close(); } catch(Exception e) {}
        try { if (stmt != null) stmt.close(); } catch(Exception e) {}
        try { if (conn != null) conn.close(); } catch(Exception e) {}
    }
}
%>

<html>
<head>
<title>SQL Injection Test</title>
</head>
<body>
<h2>SQL Injection Test</h2>

<form method="GET"action="login.jsp">
<input type="text"name="id"placeholder="ID">
<input type="text"name="pw"placeholder="Password">
<button type="submit">Login</button>
</form>

<hr>
<p><%= result %></p>
</body>
</html>
