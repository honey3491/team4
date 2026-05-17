<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStreamReader" %>
<%@ page import="java.lang.management.ManagementFactory" %>
<%@ page import="java.net.InetAddress" %>
<%@ page import="java.nio.charset.StandardCharsets" %>
<%@ page import="java.time.LocalDateTime" %>
<%@ page import="java.time.ZoneId" %>
<%@ page import="java.time.format.DateTimeFormatter" %>
<%@ page import="java.util.LinkedHashMap" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.concurrent.TimeUnit" %>

<%!
    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }

        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '&':
                    escaped.append("&amp;");
                    break;
                case '<':
                    escaped.append("&lt;");
                    break;
                case '>':
                    escaped.append("&gt;");
                    break;
                case '"':
                    escaped.append("&quot;");
                    break;
                case '\'':
                    escaped.append("&#x27;");
                    break;
                default:
                    escaped.append(ch);
            }
        }
        return escaped.toString();
    }

    private String normalizeAction(String value) {
        if (value == null) {
            return "";
        }

        String trimmed = value.trim();
        if (trimmed.length() > 30) {
            trimmed = trimmed.substring(0, 30);
        }
        return trimmed.replaceAll("[^a-z_]", "");
    }

    private boolean containsBlockedShellChars(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String[] blockedTokens = new String[] {
            "&", "&&", "|", "||", ";", "`", "$(", "<", ">", "%", "^"
        };

        for (int i = 0; i < blockedTokens.length; i++) {
            if (value.contains(blockedTokens[i])) {
                return true;
            }
        }
        return false;
    }

    private String[] resolveBinary(String[][] candidates) {
        for (int i = 0; i < candidates.length; i++) {
            String[] candidate = candidates[i];
            java.io.File file = new java.io.File(candidate[0]);
            if (file.isFile() && file.canExecute()) {
                return candidate;
            }
        }
        return null;
    }

    private String[] resolveAllowedCommand(String actionKey) {
        if ("time_snapshot".equals(actionKey)) {
            return resolveBinary(new String[][] {
                { "/bin/date", "+%Y-%m-%d %H:%M:%S %Z" },
                { "/usr/bin/date", "+%Y-%m-%d %H:%M:%S %Z" }
            });
        }
        if ("host_summary".equals(actionKey)) {
            return resolveBinary(new String[][] {
                { "/bin/hostname", "-f" },
                { "/usr/bin/hostname", "-f" },
                { "/bin/hostname" },
                { "/usr/bin/hostname" }
            });
        }
        if ("uptime_check".equals(actionKey)) {
            return resolveBinary(new String[][] {
                { "/usr/bin/uptime", "-p" },
                { "/bin/uptime", "-p" },
                { "/usr/bin/uptime" },
                { "/bin/uptime" }
            });
        }
        if ("kernel_info".equals(actionKey)) {
            return resolveBinary(new String[][] {
                { "/bin/uname", "-sr" },
                { "/usr/bin/uname", "-sr" }
            });
        }
        return null;
    }

    private String readStream(java.io.InputStream stream) throws Exception {
        StringBuilder output = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
        String line;
        int lineCount = 0;

        while ((line = reader.readLine()) != null) {
            output.append(line).append('\n');
            lineCount++;
            if (lineCount >= 30) {
                output.append("[output truncated]\n");
                break;
            }
        }

        return output.toString().trim();
    }
%>

<%
    request.setCharacterEncoding("UTF-8");
    response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");

    String selectedAction = normalizeAction(request.getParameter("action"));
    String commandInput = request.getParameter("cmd");
    String normalizedInput = normalizeAction(commandInput);

    String apiMessage = "";
    String apiOutput = "";
    String apiResultClass = "board-error";

    String commandMessage = "";
    String commandOutput = "";
    String commandResultClass = "board-error";

    if ("POST".equalsIgnoreCase(request.getMethod())) {
        if ("api".equals(selectedAction)) {
            try {
                Map diagnostics = new LinkedHashMap();
                diagnostics.put("서버 현재 시간", LocalDateTime.now(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                diagnostics.put("호스트 이름", InetAddress.getLocalHost().getHostName());
                diagnostics.put("서비스 리전", ZoneId.systemDefault().toString());
                diagnostics.put("운영체제", System.getProperty("os.name", "unknown") + " " + System.getProperty("os.version", ""));
                diagnostics.put("JVM 업타임", String.valueOf(ManagementFactory.getRuntimeMXBean().getUptime() / 1000) + "s");
                diagnostics.put("가용 메모리(MB)", String.valueOf(Runtime.getRuntime().freeMemory() / (1024 * 1024)));

                StringBuilder builder = new StringBuilder();
                java.util.Iterator iterator = diagnostics.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry entry = (Map.Entry) iterator.next();
                    builder.append(entry.getKey()).append(" : ").append(entry.getValue()).append('\n');
                }

                apiResultClass = "board-success";
                apiMessage = "플랫폼 API 기반 상태 스냅샷을 조회했습니다.";
                apiOutput = builder.toString().trim();
            } catch (Exception e) {
                apiMessage = "상태 스냅샷 조회 중 오류가 발생했습니다: " + e.getMessage();
            }
        } else if ("validated".equals(selectedAction)) {
            if (commandInput == null || commandInput.trim().isEmpty()) {
                commandMessage = "실행할 작업 코드를 입력해야 합니다.";
            } else if (containsBlockedShellChars(commandInput)) {
                commandMessage = "입력값에 차단된 특수문자가 포함되어 있습니다. &, &&, |, ||, ;, `, $(), <, >, %, ^ 는 허용되지 않습니다.";
            } else if (!commandInput.equals(normalizedInput)) {
                commandMessage = "허용된 영문 소문자와 밑줄 형식의 작업 코드만 입력할 수 있습니다.";
            } else {
                String[] command = resolveAllowedCommand(normalizedInput);
                if (command == null) {
                    commandMessage = "허용 목록에 없는 작업입니다. time_snapshot, host_summary, uptime_check, kernel_info 중에서만 선택할 수 있습니다.";
                } else {
                    Process process = null;
                    try {
                        ProcessBuilder pb = new ProcessBuilder(command);
                        pb.redirectErrorStream(true);
                        process = pb.start();

                        boolean finished = process.waitFor(3, TimeUnit.SECONDS);
                        if (!finished) {
                            process.destroyForcibly();
                            commandMessage = "작업 실행 시간이 제한을 초과했습니다.";
                        } else {
                            commandOutput = readStream(process.getInputStream());
                            if (process.exitValue() == 0) {
                                commandResultClass = "board-success";
                                commandMessage = "승인된 운영 작업을 검증 후 실행했습니다.";
                            } else {
                                commandMessage = "승인된 작업이지만 정상 종료하지 않았습니다.";
                            }
                        }
                    } catch (Exception e) {
                        commandMessage = "검증 기반 작업 실행 중 오류가 발생했습니다: " + e.getMessage();
                    } finally {
                        if (process != null) {
                            try { process.getInputStream().close(); } catch (Exception e) {}
                            try { process.getErrorStream().close(); } catch (Exception e) {}
                            try { process.getOutputStream().close(); } catch (Exception e) {}
                        }
                    }
                }
            }
        }
    }
%>

<%@ include file="header.jsp" %>

<style>
.ops-wrap {
    max-width: 900px;
    margin: 40px auto;
    padding: 0 20px;
}

.ops-header {
    margin-bottom: 28px;
}

.ops-badge {
    font-size: 12px;
    color: #64748b;
    font-weight: 600;
}

.ops-header h2 {
    margin: 6px 0 8px;
    font-size: 28px;
}

.ops-header p {
    margin: 0;
    color: #64748b;
    line-height: 1.6;
}

.ops-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 20px;
}

.ops-card {
    background: #fff;
    border: 1px solid #e5e7eb;
    border-radius: 14px;
    padding: 22px;
    box-shadow: 0 4px 14px rgba(0,0,0,0.04);
}

.ops-card h3 {
    margin: 0 0 8px;
    font-size: 18px;
}

.ops-card p {
    margin: 0 0 18px;
    color: #64748b;
    font-size: 14px;
    line-height: 1.5;
}

.ops-form label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    font-size: 14px;
}

.ops-input {
    width: 100%;
    box-sizing: border-box;
    padding: 11px 12px;
    border: 1px solid #cbd5e1;
    border-radius: 10px;
    font-size: 14px;
    margin-bottom: 12px;
}

.ops-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 16px;
}

.ops-tags span {
    padding: 6px 10px;
    border-radius: 999px;
    background: #f1f5f9;
    color: #475569;
    font-size: 12px;
}

.ops-btn {
    border: 0;
    border-radius: 10px;
    padding: 11px 16px;
    background: #2563eb;
    color: white;
    font-weight: 700;
    cursor: pointer;
}

.ops-btn:hover {
    background: #1d4ed8;
}

.ops-result {
    margin-top: 18px;
    padding: 14px;
    border-radius: 10px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
}

.ops-result-title {
    font-weight: 700;
    margin-bottom: 8px;
}

.ops-output {
    margin: 0;
    white-space: pre-wrap;
    font-size: 13px;
    color: #334155;
}

@media (max-width: 760px) {
    .ops-grid {
        grid-template-columns: 1fr;
    }
}
</style>

<main class="ops-wrap">
    <header class="ops-header">
        <div class="ops-badge">Internal Operations Console</div>
        <h2>운영 상태 센터</h2>
        <p>서비스 상태 확인과 승인된 읽기 전용 운영 작업을 수행합니다.</p>
    </header>

    <div class="ops-grid">
        <section class="ops-card">
            <h3>상태 스냅샷</h3>
            <p>Java API 기반으로 서버 상태를 조회합니다.</p>

            <form method="post" action="command.jsp">
                <input type="hidden" name="action" value="api">
                <button type="submit" class="ops-btn">새로고침</button>
            </form>

            <% if (!apiMessage.isEmpty()) { %>
                <div class="ops-result">
                    <div class="ops-result-title"><%= escapeHtml(apiMessage) %></div>
                    <% if (!apiOutput.isEmpty()) { %>
                        <pre class="ops-output"><%= escapeHtml(apiOutput) %></pre>
                    <% } %>
                </div>
            <% } %>
        </section>

        <section class="ops-card">
            <h3>승인된 운영 작업</h3>
            <p>허용된 작업 코드만 검증 후 실행합니다.</p>

            <form method="post" action="command.jsp" class="ops-form" autocomplete="off">
                <input type="hidden" name="action" value="validated">

                <label for="cmd">작업 코드</label>
                <input
                    type="text"
                    id="cmd"
                    name="cmd"
                    class="ops-input"
                    maxlength="30"
                    placeholder="예: time_snapshot"
                    value="<%= escapeHtml(commandInput == null ? "" : commandInput) %>"
                >

                <div class="ops-tags">
                    <span>time_snapshot</span>
                    <span>host_summary</span>
                    <span>uptime_check</span>
                    <span>kernel_info</span>
                </div>

                <button type="submit" class="ops-btn">실행</button>
            </form>

            <% if (!commandMessage.isEmpty()) { %>
                <div class="ops-result">
                    <div class="ops-result-title"><%= escapeHtml(commandMessage) %></div>
                    <% if (!commandOutput.isEmpty()) { %>
                        <pre class="ops-output"><%= escapeHtml(commandOutput) %></pre>
                    <% } %>
                </div>
            <% } %>
        </section>
    </div>
</main>

<%@ include file="footer.jsp" %>
