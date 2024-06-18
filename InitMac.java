import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class InitMac {

    public static void main(String[] args) throws Exception {
        // Scenario 1: Same secret key, same text
        SecretKey sk1 = generateSecretKey();
        byte[] mac1 = calculateMAC(sk1, "Hi");
        System.out.println("MAC with same key, same text: " + toHexString(mac1));

        // Scenario 2: Same secret key, different text
        byte[] mac2 = calculateMAC(sk1, "Hello");
        System.out.println("MAC with same key, different text: " + toHexString(mac2));

        // Scenario 3: Different secret key, same text
        SecretKey sk2 = generateSecretKey();
        byte[] mac3 = calculateMAC(sk2, "Hi");
        System.out.println("MAC with different key, same text: " + toHexString(mac3));
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
        return kg.generateKey();
    }

    private static byte[] calculateMAC(SecretKey key, String text) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(text.getBytes());
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
