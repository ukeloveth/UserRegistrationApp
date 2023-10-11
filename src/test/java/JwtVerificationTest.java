import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class JwtVerificationTest {

    @Test
    public void testValidJwtVerification() {
        String secretKey = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.OVU8U4h0E40cH037TpE88yANhgJZERgsn3mEt-VHdZg";

//        byte[] secretKeyBytes = "your_secret_key".getBytes();
//        SecretKey secretKey = Keys.hmacShaKeyFor(secretKeyBytes);
//        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String username = "user123";

        String validJwt = UserRegistrationApp.generateJwt(username, secretKey);

        String result = UserRegistrationApp.verifyJwt(validJwt, secretKey);
//        String result = UserRegistrationApp.verifyJwt(validJwt, secretKey);

        assertEquals("Verification pass", result);
    }

//    @Test
//    public void testValidJwtVerification() {
//        String secretKey = "your_secret_key";
//        String username = "user123";
//
//        String validJwt = UserRegistrationApp.generateJwt(username, secretKey);
//
//        String result = UserRegistrationApp.verifyJwt(validJwt, secretKey);
//
//        assertEquals("Verification pass", result);
//    }

    @Test
    public void testInvalidJwtVerification() {
        String secretKey = "your_secret_key";

        String invalidJwt = generateInvalidJwt(secretKey);

        String result = UserRegistrationApp.verifyJwt(invalidJwt, secretKey);

        assertEquals("Verification fails", result);
    }

    private String generateInvalidJwt(String secretKey) {
        try {
            String yourSecretKey = "your_secret_key";

            Claims claims = Jwts.claims();
            claims.put("username", "user123");
            claims.put("role", "admin");

            long expirationMillis = System.currentTimeMillis() - 10000; // 10 seconds ago
            Date expiration = new Date(expirationMillis);

            String invalidJwt = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(new Date())
                    .setExpiration(expiration)
                    .signWith(SignatureAlgorithm.HS256, yourSecretKey)
                    .compact();

            return invalidJwt;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate an intentionally invalid JWT.", e);
        }
    }

}


