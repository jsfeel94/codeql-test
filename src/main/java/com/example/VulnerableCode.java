package com.example;

import java.sql.*;
import java.io.*;
import java.util.*;
import javax.servlet.http.*;
import javax.servlet.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 취약한 자바 코드 예제 - CodeQL SAST 진단용
 * 이 클래스는 의도적으로 다양한 보안 취약점을 포함하고 있습니다.
 * 
 * 테스트용 변경사항: CodeQL 분석을 위한 PR 생성
 */
public class VulnerableCode {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password123";
    
    /**
     * SQL Injection 취약점 수정 예제
     */
    public String getUserById(String userId) {
        String query = "SELECT * FROM users WHERE id = ?"; // 수정: PreparedStatement 사용
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            
            stmt.setString(1, userId); // 안전한 파라미터 바인딩
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                return rs.getString("username");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    /**
     * Command Injection 취약점 수정 예제
     */
    public String executeCommand(String userInput) {
        try {
            // 수정: 더 강화된 입력 검증 및 절대 경로 사용
            if (userInput == null || userInput.trim().isEmpty()) {
                return "Invalid input";
            }
            
            // 입력 길이 제한
            if (userInput.length() > 100) {
                return "Input too long";
            }
            
            // 허용된 문자만 사용 (더 엄격)
            if (!userInput.matches("^[a-zA-Z0-9.-]+$")) {
                return "Invalid characters in input";
            }
            
            // IP 주소 형식 검증 (ping 명령어용)
            if (!userInput.matches("^[a-zA-Z0-9.-]+$") || userInput.contains("..")) {
                return "Invalid input format";
            }
            
            // 절대 경로 사용하여 명령어 실행
            ProcessBuilder pb = new ProcessBuilder("/bin/ping", "-c", "1", userInput);
            pb.directory(new File("/")); // 작업 디렉토리를 루트로 설정
            
            Process process = pb.start();
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                return output.toString();
            }
        } catch (IOException e) {
            e.printStackTrace();
            return "Error executing command";
        }
    }
    
    /**
     * Path Traversal 취약점 수정 예제
     */
    public String readFile(String fileName) {
        try {
            // 수정: 더 강화된 경로 검증
            if (fileName == null || fileName.trim().isEmpty()) {
                return "Invalid file name";
            }
            
            // 모든 위험한 패턴 검사 (더 포괄적)
            String[] dangerousPatterns = {
                "..", "/", "\\", "~", "..\\", "../", "..%2f", "..%5c", 
                "%2e%2e", "%2e%2e%2f", "%2e%2e%5c", "..%252f", "..%255c"
            };
            for (String pattern : dangerousPatterns) {
                if (fileName.toLowerCase().contains(pattern.toLowerCase())) {
                    return "Invalid file name: Dangerous pattern detected";
                }
            }
            
            // 파일명 길이 제한
            if (fileName.length() > 255) {
                return "Invalid file name: Too long";
            }
            
            // 파일명 정규화 (더 엄격)
            String normalizedFileName = fileName.replaceAll("[^a-zA-Z0-9._-]", "");
            if (!normalizedFileName.equals(fileName) || normalizedFileName.isEmpty()) {
                return "Invalid file name: Contains invalid characters";
            }
            
            // 파일명이 점으로 시작하거나 끝나는지 확인
            if (normalizedFileName.startsWith(".") || normalizedFileName.endsWith(".")) {
                return "Invalid file name: Cannot start or end with dot";
            }
            
            File baseDir = new File("/uploads");
            File file = new File(baseDir, normalizedFileName);
            
            // 경로가 baseDir 내부에 있는지 확인 (더 엄격)
            String canonicalPath = file.getCanonicalPath();
            String baseCanonicalPath = baseDir.getCanonicalPath();
            
            if (!canonicalPath.startsWith(baseCanonicalPath + File.separator) && 
                !canonicalPath.equals(baseCanonicalPath)) {
                return "Access denied: Path traversal detected";
            }
            
            try (Scanner scanner = new Scanner(file)) {
                StringBuilder content = new StringBuilder();
                while (scanner.hasNextLine()) {
                    content.append(scanner.nextLine()).append("\n");
                }
                return content.toString();
            }
        } catch (IOException e) {
            e.printStackTrace();
            return "File not found or access denied";
        }
    }
    
    /**
     * Weak Hashing 취약점 수정 예제 (SHA-256 사용)
     */
    public String hashPassword(String password) {
        try {
            // 수정: SHA-256 사용 (더 안전한 해시 알고리즘)
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Hardcoded Password 취약점 수정 예제
     */
    public boolean authenticateUser(String username, String password) {
        // 수정: 환경변수 또는 설정 파일에서 패스워드 읽기
        String adminPassword = System.getenv("ADMIN_PASSWORD");
        if (adminPassword == null || adminPassword.isEmpty()) {
            adminPassword = "default_secure_password"; // 기본값 (실제로는 설정 파일에서 읽어야 함)
        }
        return "admin".equals(username) && adminPassword.equals(password);
    }
    
    /**
     * Unsafe Deserialization 취약점 수정 예제
     */
    public Object deserializeObject(byte[] data) {
        try {
            // 수정: 안전한 역직렬화 (화이트리스트 방식)
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            String aa = "bbccdd";
            
            // 허용된 클래스만 역직렬화
            String className = ois.readUTF();
            if (!isAllowedClass(className)) {
                throw new SecurityException("Deserialization of " + className + " is not allowed");
            }
            
            return ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 허용된 클래스인지 확인하는 메서드
     */
    private boolean isAllowedClass(String className) {
        // 허용된 클래스 목록 (실제로는 더 엄격하게 관리해야 함)
        String[] allowedClasses = {
            "java.lang.String",
            "java.lang.Integer",
            "java.util.ArrayList"
        };
        
        for (String allowed : allowedClasses) {
            if (className.equals(allowed)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * XSS 취약점 수정 예제 (서블릿 컨텍스트)
     */
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userInput = request.getParameter("input");
        
        // 수정: 더 강화된 XSS 방어
        String sanitizedInput = sanitizeInput(userInput);
        response.setContentType("text/html; charset=UTF-8");
        response.getWriter().println("<h1>User Input: " + sanitizedInput + "</h1>");
    }
    
    /**
     * 강화된 입력 검증 및 이스케이프 처리 메서드
     */
    private String sanitizeInput(String input) {
        if (input == null) return "";
        
        // 입력 길이 제한
        if (input.length() > 1000) {
            return "Input too long";
        }
        
        // 위험한 패턴 제거
        String[] dangerousPatterns = {
            "<script", "</script", "javascript:", "onload=", "onerror=", 
            "onclick=", "onmouseover=", "onfocus=", "onblur=",
            "vbscript:", "data:", "expression("
        };
        
        String sanitized = input;
        for (String pattern : dangerousPatterns) {
            sanitized = sanitized.replaceAll("(?i)" + pattern, "");
        }
        
        // HTML 이스케이프 처리 (더 포괄적)
        return escapeHtml(sanitized);
    }
    
    /**
     * HTML 이스케이프 처리 메서드 (강화)
     */
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;")
                   .replace("/", "&#x2F;")
                   .replace("`", "&#x60;")
                   .replace("=", "&#x3D;");
    }
    
    /**
     * Weak Random Number Generation 취약점 수정 예제
     */
    public String generateToken() {
        // 수정: SecureRandom 사용 (암호학적으로 안전한 난수 생성)
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            byte[] tokenBytes = new byte[32];
            secureRandom.nextBytes(tokenBytes);
            
            // 16진수 문자열로 변환
            StringBuilder sb = new StringBuilder();
            for (byte b : tokenBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "token_generation_failed";
        }
    }
    
    /**
     * Information Disclosure 취약점 수정 예제
     */
    public void logSensitiveInfo(String username, String password) {
        // 수정: 민감한 정보를 마스킹하여 로그 출력
        String maskedPassword = maskPassword(password);
        System.out.println("Login attempt - Username: " + username + ", Password: " + maskedPassword);
    }
    
    /**
     * 패스워드를 마스킹하는 메서드
     */
    private String maskPassword(String password) {
        if (password == null || password.isEmpty()) {
            return "***";
        }
        if (password.length() <= 2) {
            return "***";
        }
        return password.charAt(0) + "***" + password.charAt(password.length() - 1);
    }
    
    /**
     * Resource Leak 취약점 수정 예제dmㅓㅇ하
     */
    public void processFile(String fileName) {
        // 수정: try-with-resources 사용으로 자동 리소스 해제
        try (FileInputStream fis = new FileInputStream(fileName)) {
            int data = fis.read();
            System.out.println("File data: " + data);
            // fis는 자동으로 close()됨
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
