package src.main.com.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class Aes256Example {

    // 定义加密算法、工作模式和填充方式
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    // GCM 模式推荐的参数
    private static final int TAG_LENGTH_BIT = 128; // 认证标签长度（位）
    private static final int IV_LENGTH_BYTE = 12;   // IV 长度（字节）

    /**
     * 生成一个随机的 AES-256 密钥
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256, new SecureRandom()); // 明确指定 256 位
        return keyGenerator.generateKey();
    }

    /**
     * 加密方法
     * @param plainText 待加密的明文
     * @param key 256位密钥
     * @return 返回 Base64 编码的字符串（包含 IV + 密文）
     */
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        // 1. 生成随机 IV
        byte[] iv = new byte[IV_LENGTH_BYTE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 2. 初始化 Cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        // 3. 执行加密
        byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));

        // 4. 将 IV 和 密文 拼接在一起，方便传输/存储
        byte[] cipherTextWithIv = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.length);
        System.arraycopy(cipherText, 0, cipherTextWithIv, iv.length, cipherText.length);

        // 5. 转换为 Base64 字符串返回
        return Base64.getEncoder().encodeToString(cipherTextWithIv);
    }

    /**
     * 解密方法
     * @param encryptedTextWithIv 加密后的 Base64 字符串（包含 IV + 密文）
     * @param key 256位密钥
     * @return 解密后的明文
     */
    public static String decrypt(String encryptedTextWithIv, SecretKey key) throws Exception {
        // 1. 将 Base64 字符串解码为字节数组
        byte[] cipherTextWithIv = Base64.getDecoder().decode(encryptedTextWithIv);

        // 2. 提取 IV
        byte[] iv = new byte[IV_LENGTH_BYTE];
        System.arraycopy(cipherTextWithIv, 0, iv, 0, iv.length);

        // 3. 提取真正的密文
        int cipherTextLength = cipherTextWithIv.length - IV_LENGTH_BYTE;
        byte[] cipherText = new byte[cipherTextLength];
        System.arraycopy(cipherTextWithIv, IV_LENGTH_BYTE, cipherText, 0, cipherTextLength);

        // 4. 初始化 Cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        // 5. 执行解密
        byte[] plainText = cipher.doFinal(cipherText);

        return new String(plainText, "UTF-8");
    }

    // 运行测试
    public static void main(String[] args) {
        try {
            String originalText = "Hello World! 这是一条需要加密的秘密消息。";
            System.out.println("【原始明文】: " + originalText);

            // 1. 生成 256 位密钥
            SecretKey secretKey = generateKey();

            // 如果你想用自定义的字符串作密钥（必须凑满32字节/256位）:
            // byte[] keyBytes = "12345678123456781234567812345678".getBytes("UTF-8");
            // SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            // 2. 加密
            String encryptedData = encrypt(originalText, secretKey);
            System.out.println("【加密密文 (Base64)】: " + encryptedData);

            // 3. 解密
            String decryptedText = decrypt(encryptedData, secretKey);
            System.out.println("【解密明文】: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
