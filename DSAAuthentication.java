import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

public class DSAAuthentication {
    public static void main(String[] args) throws Exception {
        // Sample message
        String originalMessage = "test message";

        // Sender's process
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        Signature dsa = Signature.getInstance("SHA256withDSA");
        PrivateKey priv = pair.getPrivate();
        dsa.initSign(priv);

        dsa.update(originalMessage.getBytes());
        byte[] signature = dsa.sign();

        // Sending message, signature, and public key to Verifier
        PublicKey pub = pair.getPublic();

        // Verifier's process
        Signature verifierSig = Signature.getInstance("SHA256withDSA");
        verifierSig.initVerify(pub);

        verifierSig.update(originalMessage.getBytes());
        boolean verifies = verifierSig.verify(signature);

        System.out.println("Signature verifies: " + verifies);
    }

    // Function to simulate tampering (for testing purposes)
    public static void tamperData(byte[] data) {
        data[0] = (byte) (data[0] + 1);
    }
}
