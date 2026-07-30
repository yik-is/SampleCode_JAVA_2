package src.main.com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class EcdsaExample {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        String message = "这是一条需要签名的数据，用来证明发送者的身份。";

        // ==========================================
        // 1. 生成 ECDSA 密钥对 (使用 P-256 / secp256r1 曲线)
        // ==========================================
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair ecKeyPair = kpg.generateKeyPair();

        // ==========================================
        // 2. 签名方：用【私钥】对数据进行数字签名
        // ==========================================
        Signature signer = Signature.getInstance("SHA256withECDSA", "BC");
        signer.initSign(ecKeyPair.getPrivate());
        signer.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign();

        System.out.println("--- ECDSA 签名完成 ---");
        System.out.println("签名结果 (Base64): " + Base64.getEncoder().encodeToString(signature));

        // ==========================================
        // 3. 验证方：用【公钥】验证签名是否有效
        // ==========================================
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(ecKeyPair.getPublic());
        verifier.update(message.getBytes(StandardCharsets.UTF_8));
        boolean isValid = verifier.verify(signature); // 验证

        System.out.println("\n--- ECDSA 验证完成 ---");
        System.out.println("签名是否合法: " + isValid);
    }
}
