package com.example;

import java.sql.*;
import java.io.*;
import java.util.*;
import javax.servlet.http.*;
import javax.servlet.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
     * Hardcoded Password 취약점 예제
     */
    public boolean authenticateUser(String username, String password) {
        // 취약점: 하드코딩된 패스워드
        String adminPassword = "admin123";
        return "admin".equals(username) && adminPassword.equals(password);
    }
    
    /**
     * Unsafe Deserialization 취약점 예제
     */
    public Object deserializeObject(byte[] data) {
        try {
            // 취약점: 안전하지 않은 역직렬화
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            return ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
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
     * Weak Random Number Generation 취약점 예제
     */
    public String generateToken() {
        // 취약점: Random 클래스는 예측 가능
        Random random = new Random();
        return String.valueOf(random.nextInt(1000000));
    }
    
    /**
     * Information Disclosure 취약점 예제
     */
    public void logSensitiveInfo(String username, String password) {
        // 취약점: 민감한 정보를 로그에 출력
        System.out.println("Login attempt - Username: " + username + ", Password: " + password);
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
