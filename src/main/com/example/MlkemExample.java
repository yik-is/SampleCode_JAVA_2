package src.main.com.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;

class MlkemExample {

    public static void main(String[] args) {
        try {
            System.out.println("=== ML-KEM (Kyber) 后量子密钥封装示例 ===");

            // 1. 初始化密钥对生成器（使用 ML-KEM-768 参数）
            SecureRandom random = new SecureRandom();
            MLKEMKeyPairGenerator keyPairGenerator = new MLKEMKeyPairGenerator();

            // MLKEMParameters 包含 ml_kem_512, ml_kem_768, ml_kem_1024
            keyPairGenerator.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));

            // 2. 生成后量子密钥对
            System.out.println("\n[步骤 1] 正在生成 ML-KEM 密钥对...");
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
            MLKEMPublicKeyParameters publicKey = (MLKEMPublicKeyParameters) keyPair.getPublic();
            MLKEMPrivateKeyParameters privateKey = (MLKEMPrivateKeyParameters) keyPair.getPrivate();

            System.out.println("公钥生成成功，长度: " + publicKey.getEncoded().length + " 字节");
            System.out.println("私钥生成成功，长度: " + privateKey.getEncoded().length + " 字节");

            // -------------------------------------------------------------------------

            // 3. 封装阶段 (Encapsulation) - 通常由“发送方”执行
            // 发送方利用接收方的公钥，生成一个“共享密钥”和一段“密文(封装后的数据)”
            System.out.println("\n[步骤 2] 发送方使用公钥进行密钥封装 (Encapsulation)...");
            MLKEMGenerator generator = new MLKEMGenerator(random);

            SecretWithEncapsulation encapsulationResult =
                    generator.generateEncapsulated(publicKey);

            byte[] senderSharedKey = encapsulationResult.getSecret();
            byte[] cipherText = encapsulationResult.getEncapsulation();

            System.out.println("生成的共享密钥 (发送方): " + Hex.toHexString(senderSharedKey));
            System.out.println("生成的封装密文 (需传送): " +
                    Hex.toHexString(cipherText).substring(0, 60) + "...");

            // -------------------------------------------------------------------------

            // 4. 解封装阶段 (Decapsulation) - 通常由“接收方”执行
            // 接收方收到密文后，用自己的私钥解出相同的“共享密钥”
            System.out.println("\n[步骤 3] 接收方使用私钥进行解封装 (Decapsulation)...");
            MLKEMExtractor extractor = new MLKEMExtractor(privateKey);

            byte[] receiverSharedKey = extractor.extractSecret(cipherText);

            System.out.println("解封装后的共享密钥 (接收方): " + Hex.toHexString(receiverSharedKey));

            System.out.println("解封装后的共享密钥 (接收方): " + Hex.toHexString(receiverSharedKey));

            // -------------------------------------------------------------------------

            // 5. 验证两个密钥是否一致
            System.out.println("\n[步骤 4] 验证双方密钥是否同步...");
            boolean isSuccess = java.util.Arrays.equals(senderSharedKey, receiverSharedKey);
            if (isSuccess) {
                System.out.println("🎉 成功！双方已安全协商出相同的后量子共享密钥。");
                System.out.println("此密钥现在可以安全地用于 AES-256 加密你的实际业务数据了！");
            } else {
                System.out.println("❌ 失败！密钥不匹配。");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
