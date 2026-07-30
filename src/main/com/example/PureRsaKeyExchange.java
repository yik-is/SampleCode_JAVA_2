package src.main.com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Base64;

public class PureRsaKeyExchange {

    static {
        // 注册 Bouncy Castle 密码学提供者
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // ====================================================
        // 1. 准备工作：生成接收方的 RSA 密钥对（公钥和私钥）
        // ====================================================
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(3072); // 现代安全标准推荐 3072 位
        KeyPair rsaKeyPair = kpg.generateKeyPair();

        System.out.println("--- 1. 接收方生成了 RSA 密钥对 ---");

        // ====================================================
        // 2. 发送方：生成一个要交换的 256 位（32字节）随机密钥
        // ====================================================
        byte[] secretToExchange = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(secretToExchange); // 填充随机数据

        System.out.println("--- 2. 发送方生成的原始密钥 (Base64): "
                + Base64.getEncoder().encodeToString(secretToExchange));

        // ====================================================
        // 3. 发送方：用接收方的 RSA 公钥加密这个密钥
        // ====================================================
        // 使用目前最安全的 OAEP 填充模式
        Cipher encryptCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());

        // 这就是要在网络上传输的加密后的密钥数据
        byte[] encryptedKey = encryptCipher.doFinal(secretToExchange);

        System.out.println("--- 3. 发送方使用 RSA 公钥加密完成 ---");
        System.out.println("加密后的密钥网络传输形式 (Base64): "
                + Base64.getEncoder().encodeToString(encryptedKey));

        // ====================================================
        // 4. 接收方：收到加密数据后，用自己的 RSA 私钥解密
        // ====================================================
        Cipher decryptCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
        decryptCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());

        // 解密恢复出原始密钥
        byte[] decryptedSecret = decryptCipher.doFinal(encryptedKey);

        System.out.println("--- 4. 接收方使用 RSA 私钥解密完成 ---");
        System.out.println("解密出来的密钥 (Base64): "
                + Base64.getEncoder().encodeToString(decryptedSecret));
    }
}
