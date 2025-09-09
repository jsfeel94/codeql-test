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
 */
public class VulnerableCode {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password123";
    
    /**
     * SQL Injection 취약점 예제
     */
    public String getUserById(String userId) {
        String query = "SELECT * FROM users WHERE id = " + userId; // 취약점: SQL Injection
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                return rs.getString("username");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    /**
     * Command Injection 취약점 예제
     */
    public String executeCommand(String userInput) {
        try {
            // 취약점: Command Injection
            Process process = Runtime.getRuntime().exec("ping " + userInput);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return "Error executing command";
        }
    }
    
    /**
     * Path Traversal 취약점 예제
     */
    public String readFile(String fileName) {
        try {
            // 취약점: Path Traversal
            File file = new File("/uploads/" + fileName);
            Scanner scanner = new Scanner(file);
            StringBuilder content = new StringBuilder();
            while (scanner.hasNextLine()) {
                content.append(scanner.nextLine()).append("\n");
            }
            scanner.close();
            return content.toString();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return "File not found";
        }
    }
    
    /**
     * Weak Hashing 취약점 예제 (MD5 사용)
     */
    public String hashPassword(String password) {
        try {
            // 취약점: MD5는 취약한 해시 알고리즘
            MessageDigest md = MessageDigest.getInstance("MD5");
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
     * XSS 취약점 예제 (서블릿 컨텍스트)
     */
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userInput = request.getParameter("input");
        
        // 취약점: 사용자 입력을 그대로 출력 (XSS)
        response.getWriter().println("<h1>User Input: " + userInput + "</h1>");
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
     * Resource Leak 취약점 예제
     */
    public void processFile(String fileName) {
        try {
            FileInputStream fis = new FileInputStream(fileName);
            // 취약점: 리소스가 제대로 닫히지 않음
            int data = fis.read();
            System.out.println("File data: " + data);
            // fis.close()가 호출되지 않음
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
