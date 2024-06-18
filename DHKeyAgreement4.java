import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
/*
 * This program executes the Diffie-Hellman key agreement protocol between
 * 4 parties: Alice, Bob, and Carol using a shared 2048-bit DH parameter.
 */
public class DHKeyAgreement4 {
    private DHKeyAgreement4() {}
    public static void main(String argv[]) throws Exception {
        // Alice creates her own DH key pair with 2048-bit key size
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
        // This DH parameters can also be constructed by creating a
        // DHParameterSpec object using agreed-upon values
        DHParameterSpec dhParamShared = ((DHPublicKey)aliceKpair.getPublic()).getParams();
        // Bob creates his own DH key pair using the same params
        System.out.println("BOB: Generate DH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamShared);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();
        // Carol creates her own DH key pair using the same params
        System.out.println("CAROL: Generate DH keypair ...");
        KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
        carolKpairGen.initialize(dhParamShared);
        KeyPair carolKpair = carolKpairGen.generateKeyPair();
        // Dan creates her own DH key pair using the same params
        System.out.println("Dan: Generate DH keypair ...");
        KeyPairGenerator DanKpairGen = KeyPairGenerator.getInstance("DH");
        DanKpairGen.initialize(dhParamShared);
        KeyPair DanKpair = carolKpairGen.generateKeyPair();

        // Alice initialize
        System.out.println("ALICE: Initialize ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());
        // Bob initialize
        System.out.println("BOB: Initialize ...");
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());
        // Carol initialize
        System.out.println("CAROL: Initialize ...");
        KeyAgreement carolKeyAgree = KeyAgreement.getInstance("DH");
        carolKeyAgree.init(carolKpair.getPrivate());
        // Dan initialize
        System.out.println("Dan: Initialize ...");
        KeyAgreement DanKeyAgree = KeyAgreement.getInstance("DH");
        DanKeyAgree.init(DanKpair.getPrivate());

        //First Pass
        //Alice computes gSA
        Key gDA = aliceKeyAgree.doPhase(DanKpair.getPublic(), false);
        //Bob computes gAB
        Key gAB = bobKeyAgree.doPhase(aliceKpair.getPublic(), false);
        //Carol computes gBC
        Key gBC = carolKeyAgree.doPhase(bobKpair.getPublic(), false);
        //Dan computes gCS
        Key gCD = DanKeyAgree.doPhase(carolKpair.getPublic(), false);
        //Second Pass
        //Alice computes gCSA
        Key gCDA = aliceKeyAgree.doPhase(gCD, false);
        //Bob computes gSAB
        Key gDAB = bobKeyAgree.doPhase(gDA, false);
        //Carol computes gABC
        Key gABC = carolKeyAgree.doPhase(gAB, false);
        //Dan computes gBCS
        Key gBCS = DanKeyAgree.doPhase(gBC, false);
        //Third Pass
        //Alice computes gBCSA
        aliceKeyAgree.doPhase(gBCS, true); //This is Alice's secret
        //Bob computes gCSAB
        bobKeyAgree.doPhase(gCDA, true); //This is Bob's secret
        //Carol computes gSABC
        carolKeyAgree.doPhase(gDAB, true); //This is Carol's secret
        //Dan Computes gABCS
        DanKeyAgree.doPhase(gABC, true); //This is Dan's secret


        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        System.out.println("Alice secret: " + toHexString(aliceSharedSecret));
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        System.out.println("Bob secret: " + toHexString(bobSharedSecret));
        byte[] carolSharedSecret = carolKeyAgree.generateSecret();
        System.out.println("Carol secret: " + toHexString(carolSharedSecret));
        byte[] DanSharedSecret = DanKeyAgree.generateSecret();
        System.out.println("Dan secret: " + toHexString(DanSharedSecret));

        // Compare Alice and Bob
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
            throw new Exception("Alice and Bob differ");
        System.out.println("Alice and Bob are the same");
        // Compare Bob and Carol
        if (!java.util.Arrays.equals(bobSharedSecret, carolSharedSecret))
            throw new Exception("Bob and Carol differ");
        System.out.println("Bob and Carol are the same");
        if (!java.util.Arrays.equals(carolSharedSecret, DanSharedSecret))
            throw new Exception("Carol and Dan differ");
        System.out.println("Carol and Dan are the same");
        if (!java.util.Arrays.equals(DanSharedSecret, aliceSharedSecret))
            throw new Exception("Dan and Alice differ");
        System.out.println("Dan and Alice are the same");
    }
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}