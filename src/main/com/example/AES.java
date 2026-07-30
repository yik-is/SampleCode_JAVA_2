package src.main.com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

public class AES {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] deriveCombinedSecret(byte[] rsaSecret, byte[] kemSecret) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac hkdfExtract = Mac.getInstance("HmacSHA256");
        hkdfExtract.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        hkdfExtract.update(rsaSecret);
        hkdfExtract.update(kemSecret);
        byte[] prk = hkdfExtract.doFinal();

        Mac hkdfExpand = Mac.getInstance("HmacSHA256");
        hkdfExpand.init(new SecretKeySpec(prk, "HmacSHA256"));
        hkdfExpand.update("QubitSafe-Hybrid-KEM-v1".getBytes(StandardCharsets.UTF_8));
        hkdfExpand.update((byte) 0x01);
        byte[] combinedSecret = Arrays.copyOf(hkdfExpand.doFinal(), 32);
        return combinedSecret;

    }
}
