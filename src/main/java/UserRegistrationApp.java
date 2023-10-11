import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

import static java.time.LocalDate.*;
import static java.time.format.DateTimeFormatter.ISO_LOCAL_DATE;

public class UserRegistrationApp {
    public static void main(String[] args) {
        String username = "user123";
        String email = "user@example.com";
        String password = "P@ssw0rd";
        String dob = "2000-01-01";
//        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String secretKey = "your_secret_key"; // Replace 'your_secret_key' with your actual secret key

        ValidationResult validationResult = validateUserInput(username, email, password, dob);

        if (validationResult.isValid()) {
            System.out.println("All validations passed.");
//            String jwt = generateJwt(username);
            String jwt = generateJwt(username, secretKey);
            System.out.println("Generated JWT: " + jwt);

//            String result = verifyJwt(jwt);
            String result = verifyJwt(jwt, secretKey);
            System.out.println("JWT Verification Result: " + result);
        } else {
            System.out.println("Validation failed. Errors:");
            System.out.println(validationResult.getValidationErrors());
        }
    }


    public static ValidationResult validateUserInput(String username, String email, String password, String dob) {
        ValidationResult result = new ValidationResult();

        if (username == null || username.length() < 4) {
            result.addError("Username: not empty and minimum 4 characters");
        }

        if (email == null || !isValidEmail(email)) {
            result.addError("Email: not empty and valid email address");
        }

        if (password == null || !isStrongPassword(password)) {
            result.addError("Password: not empty, strong password required");
        }

        if (dob == null || !isDateOfBirthValid(dob)) {
            result.addError("Date of Birth: not empty, should be 16 years or greater");
        }

        return result;
    }

//    public static String generateJwt(String username, String secretKey) {
//        Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
//        return Jwts.builder().setSubject(username).signWith(key).compact();
//    }
//
//    public static String verifyJwt(String jwt, String secretKey) {
//        try {
//            Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
//            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt);
//            return "Verification pass";
//        } catch (JwtException e) {
//            return "Verification fails";
//        }
//    }


////    public static String generateJwt(String username) {
//    public static String generateJwt(String username, String secretKey) {
//        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
//        return Jwts.builder().setSubject(username).signWith(key).compact();
//    }
//
////    public static String verifyJwt(String jwt) {
//    public static String verifyJwt(String jwt, String secretKey) {
//        try {
//            Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
//            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt);
//            return "Verification pass";
//        } catch (JwtException e) {
//            return "Verification fails";
//        }
//    }

    public static String generateJwt(String username,String secretKey) {
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        return Jwts.builder().setSubject(username).signWith(key).compact();
    }

    public static String verifyJwt(String jwt,String secretKey) {
        try {
            Jwts.parserBuilder().setSigningKey(Keys.secretKeyFor(SignatureAlgorithm.HS256)).build().parseClaimsJws(jwt);
            return "Verification pass";
        } catch (JwtException e) {
            return "Verification fails";
        }
    }


    private static boolean isValidEmail(String email) {
        String regex = "^[A-Za-z0-9+_.-]+@(.+)$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    private static boolean isStrongPassword(String password) {
        return password.length() >= 8 && password.matches(".*[A-Z].*") && password.matches(".*[!@#$%^&*].*") && password.matches(".*\\d.*");
    }

    private static boolean isDateOfBirthValid(String dob) {
        LocalDate birthDate = parse(dob, ISO_LOCAL_DATE);
        LocalDate now = now();
        return now.minusYears(16).isAfter(birthDate);
    }
}

class ValidationResult {
    private final StringBuilder validationErrors;

    public ValidationResult() {
        this.validationErrors = new StringBuilder();
    }

    public void addError(String error) {
        if (validationErrors.length() > 0) {
            validationErrors.append(", ");
        }
        validationErrors.append(error);
    }

    public boolean isValid() {
        return validationErrors.length() == 0;
    }

    public String getValidationErrors() {
        return validationErrors.toString();
    }
}
