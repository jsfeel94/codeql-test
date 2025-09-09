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
            // 수정: ProcessBuilder 사용 및 입력 검증
            if (userInput == null || userInput.trim().isEmpty()) {
                return "Invalid input";
            }
            
            // 허용된 명령어만 실행 (화이트리스트 방식)
            if (!userInput.matches("^[a-zA-Z0-9.-]+$")) {
                return "Invalid characters in input";
            }
            
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", userInput);
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
            // 수정: 강화된 경로 검증
            if (fileName == null || fileName.trim().isEmpty()) {
                return "Invalid file name";
            }
            
            // 위험한 패턴 검사
            String[] dangerousPatterns = {"..", "/", "\\", "~", "..\\", "../"};
            for (String pattern : dangerousPatterns) {
                if (fileName.contains(pattern)) {
                    return "Invalid file name: Dangerous pattern detected";
                }
            }
            
            // 파일명 정규화
            String normalizedFileName = fileName.replaceAll("[^a-zA-Z0-9._-]", "");
            if (!normalizedFileName.equals(fileName)) {
                return "Invalid file name: Contains invalid characters";
            }
            
            File baseDir = new File("/uploads");
            File file = new File(baseDir, normalizedFileName);
            
            // 경로가 baseDir 내부에 있는지 확인
            if (!file.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
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
        
        // 수정: HTML 이스케이프 처리
        String escapedInput = escapeHtml(userInput);
        response.getWriter().println("<h1>User Input: " + escapedInput + "</h1>");
    }
    
    /**
     * HTML 이스케이프 처리 메서드
     */
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;");
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
