import java.security.*;
import javax.crypto.Cipher;

public class RSASHA1Example {

    public static void main(String[] args) throws Exception {
        // Sample input message
        String input = "This is a secure message";

        // SHA-1 Hashing
        MessageDigest sha1Digest = MessageDigest.getInstance("SHA1");
        sha1Digest.update(Utils.toByteArray(input));
        byte[] hash = sha1Digest.digest();
        System.out.println("SHA-1 Digest: " + Utils.toHex(hash));

        // RSA Encryption
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        SecureRandom random = new SecureRandom();

        // Key Generation with Timer
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        int[] keySizes = {1024, 2048, 4096};  // Different key sizes to test

        for (int keySize : keySizes) {
            long startTime = System.currentTimeMillis();  // Start timer
            keyGen.initialize(keySize, random);
            KeyPair keyPair = keyGen.generateKeyPair();
            long endTime = System.currentTimeMillis();  // End timer

            System.out.println("Time taken for " + keySize + "-bit key: " + (endTime - startTime) + " ms");
        }

        // Example with one key size (2048)
        keyGen.initialize(2048, random);  // Using a longer key for enhanced security
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypting the SHA-1 hash with RSA - Simulates signing
        rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedHash = rsaCipher.doFinal(hash);
        System.out.println("Encrypted SHA-1 Digest: " + Utils.toHex(encryptedHash));

        // Decrypting the RSA encrypted SHA-1 hash - Simulates verification
        rsaCipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedHash = rsaCipher.doFinal(encryptedHash);
        System.out.println("Decrypted SHA-1 Digest: " + Utils.toHex(decryptedHash));

        // SHA-1's vulnerability and RSA's performance
        System.out.println("Note: SHA-1 is vulnerable to collision attacks and is considered weak.");
        System.out.println("Note: RSA with longer keys is more secure but slower than symmetric key algorithms.");
    }
}
