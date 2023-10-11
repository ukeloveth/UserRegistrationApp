import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class InvalidJwtGenerator {

    public static void main(String[] args) {
        String secretKey = "your_secret_key";

        String invalidJwt = generateInvalidJwt(secretKey);

        System.out.println("Invalid JWT: " + invalidJwt);
    }

    private static String generateInvalidJwt(String secretKey) {
        Map<String, Object> tamperedPayload = new HashMap<>();
        tamperedPayload.put("username", "user123");
        tamperedPayload.put("role", "admin");

        long expirationMillis = System.currentTimeMillis() + 3600 * 1000; // 1 hour
        Date expiration = new Date(expirationMillis);

        String invalidJwt = Jwts.builder()
                .setClaims(tamperedPayload)
                .setIssuedAt(new Date())
                .setExpiration(expiration)
                .signWith(getInvalidSignature(secretKey))
                .compact();

        return invalidJwt;
    }

    private static SecretKey getInvalidSignature(String secretKey) {
        try {
            SecretKey modifiedSecretKey = Keys.hmacShaKeyFor(
                    sha256("tampered_key".getBytes(StandardCharsets.UTF_8)));

            return modifiedSecretKey;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate an intentionally invalid signature.", e);
        }
    }

    private static byte[] sha256(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }
}
