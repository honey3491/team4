## 실행 명령어

진단코드만: `python3 auto-scanner/scanner.py --target [대상URL]`<br>
대시보드:
- `pip3 install -r moduleproj2/requirements.txt`
- `streamlit moduleproj2/run app.py`

## 개요

AI 기반 웹사이트 취약점 진단 툴입니다.

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/94924e12-d91c-457c-96c4-49c444d30e0e" />
</p>

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/b5c2bd80-5705-4201-ad54-f30828b1866f" />
</p>


## 구조도

취약한 웹서버 환경
<img width="60%" alt="image" src="https://github.com/user-attachments/assets/6da87d6f-a9f7-4742-ab4f-f391e13fc27d" />

취약점 진단 시스템 구조도
<img width="60%" alt="image" src="https://github.com/user-attachments/assets/cabd2936-a75d-42b6-9caf-5233d58d0871" />


## 협업 툴

Notion [[링크]](https://www.notion.so/4-2-360b3aca18a480aa826ddada7d8fa87b?source=copy_link)
<img width="60%" alt="image" src="https://github.com/user-attachments/assets/b5c05ba2-1a0b-4877-9fc6-4fce19ff766c" />


## 기술스택

- 취약점 진단코드: Python
- LLM: GPT-5.5 (via OpenAI API)
- DB: mariaDB
- Front: streamlit
- Server: NGINX
- WAS: Tomcat
- 취약한 웹사이트: JSP

## 팀 정보

<br>
<table align="center" width="700" border="1" cellspacing="0" cellpadding="10" style="border-collapse: collapse; text-align: center;">
  <thead style="background-color: #f2f2f2;">
    <tr>
      <th width="150">성명</th>
      <th width="550">역할</th>
    </tr> 
  </thead>
  <tbody>
    <tr>
      <td>김세권</td>
      <td>
        - GPT 기반 취약점 자동진단 툴 개발<br>
        - 수동진단 시트 작성
      </td>
    </tr>
    <tr>
      <td>백하연</td>
      <td>        
        - 시그니처 기반 취약점 자동진단 툴 개발<br>
        - 취약한 웹 서버 시큐어 코딩 개발<br>
        - 협업 툴 관리
      </td>
    </tr>
    <tr>
      <td>서우혁</td>
      <td>
        - 취약점 대시보드 만들기<br>
        - 백엔드 연동 및 시각화
      </td>
    </tr>
    <tr>
      <td>이채윤</td>
      <td>
        - 취약점 대시보드 만들기<br>
        - 백엔드 연동 및 시각화
      </td>
    </tr>
    <tr>
      <td>최준희</td>
      <td>
        - 취약점 대시보드 만들기<br>
        - 백엔드 연동 및 시각과
      </td>
    </tr>
    <tr>
      <td>한병헌</td>
      <td>
        - 취약한 웹 서버 개발(Nginx, Tomcat, MariaDB)<br>
        - AWS 환경 관리
      </td>
    </tr>    
  </tbody>
</table>
<br>

## 결과 화면

#### 1. URL 기반 실시간 자동진단

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/94924e12-d91c-457c-96c4-49c444d30e0e" />
</p>

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/b5c2bd80-5705-4201-ad54-f30828b1866f" />
</p>

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/3dbd6e18-0de7-4e68-9014-4afd949ec7fd" />
</p>

---

#### 2. 자동진단 수동진단 비교

<p align="center">
  <img width="650" alt="image" src="https://github.com/user-attachments/assets/b3350575-a10a-4171-83b4-9de27f391e97" />
</p>

<p align="center">
  <img width="650" alt="image" src="https://github.com/user-attachments/assets/6e332ce6-bc10-4ff5-b825-57bae4b3a35e" />
</p>

<p align="center">
  <img width="650" alt="image" src="https://github.com/user-attachments/assets/195b5bfa-df89-408e-a750-194529e61fb2" />
</p>

<p align="center">
  <img width="650" alt="image" src="https://github.com/user-attachments/assets/4b6d99ed-f9ea-4dbc-92e3-d08a14f244e6" />
</p>

<p align="center">
  <img width="650" alt="image" src="https://github.com/user-attachments/assets/0748ca90-3524-4b49-8686-52b506b50b86" />
</p>
