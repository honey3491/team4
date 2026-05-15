<%@ page contentType="text/html; charset=UTF-8" %>

<%-- 💡 공통 헤더 포함 --%>
<%@ include file="header.jsp" %>

    <div style="border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; margin-bottom: 20px;">
        <h2 style="margin: 0; color: #d35400;">📝 새 포스트 작성 (File Upload Test)</h2>
    </div>

    <p style="margin-bottom: 1.5rem; color: #7f8c8d;">
        자유롭게 글을 작성하고 파일을 첨부해 보세요.<br>
        <strong style="color: #c0392b;">(🚨 해킹 포인트: 서버가 파일 확장자(.jsp 등)를 검사하지 않으면, 웹셸(Web Shell)을 업로드하여 시스템을 장악할 수 있습니다!)</strong>
    </p>

    <div style="background-color: #fff; padding: 20px; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
        
        <form action="upload_process.jsp" method="POST" enctype="multipart/form-data" style="display: flex; flex-direction: column; gap: 15px; margin: 0;">
            
            <div>
                <label for="title" style="font-weight: bold; display: block; margin-bottom: 5px;">제목</label>
                <input type="text" id="title" name="title" placeholder="포스트 제목을 입력하세요" required
                       style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; box-sizing: border-box;">
            </div>

            <div>
                <label for="content" style="font-weight: bold; display: block; margin-bottom: 5px;">내용</label>
                <textarea id="content" name="content" rows="10" placeholder="본문 내용을 입력하세요. (HTML 태그 입력 시 XSS 취약점 발생 가능)" required
                          style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; resize: vertical; box-sizing: border-box;"></textarea>
            </div>

            <div style="background-color: #f9f9f9; padding: 15px; border: 1px dashed #aaa; border-radius: 4px;">
                <label for="uploadFile" style="font-weight: bold; display: block; margin-bottom: 10px;">📎 첨부 파일</label>
                <input type="file" id="uploadFile" name="uploadFile" style="width: 100%; cursor: pointer;">
                <p style="color: #7f8c8d; font-size: 0.85em; margin-top: 8px; margin-bottom: 0;">
                    * 제한 없음 (모든 확장자 업로드 허용 - 취약점 실습용)
                </p>
            </div>

            <div style="text-align: right; margin-top: 10px;">
                <button type="submit" style="background-color: #27ae60; color: white; border: none; padding: 10px 25px; font-size: 1.05rem; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    🚀 포스트 등록하기
                </button>
            </div>
        </form>
    </div>

<%-- 💡 공통 푸터 포함 --%>
<%@ include file="footer.jsp" %>
