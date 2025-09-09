# SAST Demo Project - CodeQL 진단 예제

이 프로젝트는 GitHub CodeQL을 사용한 SAST(Static Application Security Testing) 진단을 위한 취약한 자바 코드 예제입니다.

## 🎯 목적

- GitHub Actions에서 CodeQL을 통한 자동 보안 진단 구성
- PR 단계에서 보안 취약점 자동 검출
- 다양한 보안 취약점 패턴 학습 및 이해

## 🔍 포함된 보안 취약점

### 1. SQL Injection
```java
String query = "SELECT * FROM users WHERE id = " + userId;
```
- **위험도**: 높음
- **설명**: 사용자 입력을 직접 SQL 쿼리에 삽입

### 2. Command Injection
```java
Process process = Runtime.getRuntime().exec("ping " + userInput);
```
- **위험도**: 높음
- **설명**: 사용자 입력을 시스템 명령어에 직접 삽입

### 3. Path Traversal
```java
File file = new File("/uploads/" + fileName);
```
- **위험도**: 높음
- **설명**: 사용자 입력을 파일 경로에 직접 사용

### 4. Cross-Site Scripting (XSS)
```java
response.getWriter().println("<h1>User Input: " + userInput + "</h1>");
```
- **위험도**: 높음
- **설명**: 사용자 입력을 HTML에 직접 출력

### 5. Weak Cryptography
```java
MessageDigest md = MessageDigest.getInstance("MD5");
```
- **위험도**: 중간
- **설명**: 취약한 해시 알고리즘 사용

### 6. Hardcoded Secrets
```java
String adminPassword = "admin123";
```
- **위험도**: 중간
- **설명**: 코드에 하드코딩된 비밀번호

### 7. Unsafe Deserialization
```java
ObjectInputStream ois = new ObjectInputStream(bis);
return ois.readObject();
```
- **위험도**: 높음
- **설명**: 안전하지 않은 객체 역직렬화

### 8. Resource Leak
```java
FileInputStream fis = new FileInputStream(fileName);
// fis.close()가 호출되지 않음
```
- **위험도**: 중간
- **설명**: 리소스가 제대로 해제되지 않음

## 🚀 GitHub Actions 설정

### CodeQL Workflow
- **파일 위치**: `.github/workflows/codeql.yml`
- **트리거**: PR 생성/업데이트, main/develop 브랜치 푸시
- **스케줄**: 매주 월요일 오전 2시

### 주요 기능
1. **자동 코드 분석**: PR 생성 시 자동으로 CodeQL 분석 실행
2. **다중 언어 지원**: Java, JavaScript, Python, C++ 등
3. **보안 및 품질 쿼리**: GitHub의 기본 보안 쿼리 세트 사용
4. **PR 코멘트**: 분석 결과를 PR에 자동 코멘트

## 🛠️ 로컬 실행

### 필요 조건
- Java 17+
- Maven 3.6+

### 빌드 및 실행
```bash
# 프로젝트 클론
git clone <repository-url>
cd 02_SAST

# 의존성 설치 및 컴파일
mvn clean compile

# 테스트 실행
mvn test

# SpotBugs 분석 실행
mvn spotbugs:check

# OWASP Dependency Check 실행
mvn org.owasp:dependency-check-maven:check
```

## 📊 분석 결과 확인

### GitHub에서 확인
1. **Security 탭**: CodeQL 분석 결과
2. **Actions 탭**: 워크플로우 실행 상태
3. **PR 코멘트**: 자동 생성된 분석 결과 요약

### 로컬에서 확인
```bash
# SpotBugs 결과
open target/spotbugs/spotbugsXml.xml

# Dependency Check 결과
open target/dependency-check-report.html
```

## 🔧 설정 파일

### Maven 설정 (`pom.xml`)
- SpotBugs 플러그인 설정
- OWASP Dependency Check 설정
- Java 17 컴파일러 설정

### CodeQL 설정 (`.github/workflows/codeql.yml`)
- 자동 분석 트리거 설정
- 다중 언어 지원
- 보안 스캔 통합

## ⚠️ 주의사항

이 프로젝트는 **교육 목적**으로 제작되었습니다:
- 실제 프로덕션 환경에서 사용하지 마세요
- 모든 코드는 의도적으로 취약점을 포함하고 있습니다
- 보안 취약점 수정 방법을 학습하는 용도로만 사용하세요

## 📚 추가 학습 자료

- [GitHub CodeQL 문서](https://docs.github.com/en/code-security/code-scanning)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Java 보안 가이드라인](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

## 🤝 기여하기

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 `LICENSE` 파일을 참조하세요.
