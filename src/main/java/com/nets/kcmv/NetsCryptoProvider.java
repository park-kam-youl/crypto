package com.nets.kcmv.provider;

import java.security.Provider;
import java.security.Security;
import java.util.Properties;
import java.util.Enumeration;

/**
 * NetsCryptoProvider
 * 
 * 국내 KCMVP 및 암호모듈 인증 환경을 위한 순수 Java 기반 Provider 예시.
 * JCE를 사용하지 않고, 자체 구현 알고리즘 클래스와 연동되는 구조를 제공합니다.
 * 
 * MagicJCryptoProvider 구조를 참조하여, KCMVP 대상 알고리즘을 등록합니다.
 */
public final class NetsCryptoProvider extends Provider {
    private static final long serialVersionUID = 1L;
    private static final String PROVIDER_NAME = "NetsCrypto";
    private static final double VERSION = 1.0;
    private static final String PROVIDER_DESC = "NetsCrypto Security Provider for KCMVP";

    private static boolean selfTested = false;
    private static boolean providerInstalled = false;

    public NetsCryptoProvider() {
        super(PROVIDER_NAME, VERSION, PROVIDER_DESC);
        registerAlgorithms();
    }

    /**
     * 내부 알고리즘 등록
     * MagicJCryptoProvider의 put() 구조를 참고하여 주요 KCMVP 대상 알고리즘들을 등록합니다.
     */
    private void registerAlgorithms() {
        // Block Ciphers
        this.put("Cipher.ARIA", "com.nets.kcmv.cipher.ARIAEngine");
        this.put("Cipher.SEED", "com.nets.kcmv.cipher.SEEDEngine");
        this.put("Cipher.LEA", "com.nets.kcmv.cipher.LEAEngine");
        this.put("Cipher.HIGHT", "com.nets.kcmv.cipher.HIGHTEngine");
        // Key Generators
        this.put("KeyGenerator.ARIA", "com.nets.kcmv.keygen.ARIAKeyGenerator");
        this.put("KeyGenerator.SEED", "com.nets.kcmv.keygen.SEEDKeyGenerator");
        this.put("KeyGenerator.LEA", "com.nets.kcmv.keygen.LEAKeyGenerator");
        this.put("KeyGenerator.HIGHT", "com.nets.kcmv.keygen.HIGHTKeyGenerator");
        // Hashes
        this.put("MessageDigest.SHA-256", "com.nets.kcmv.digest.SHA256Digest");
        this.put("MessageDigest.SHA-512", "com.nets.kcmv.digest.SHA512Digest");
        this.put("MessageDigest.LSH-256", "com.nets.kcmv.digest.LSH256Digest");
        this.put("MessageDigest.LSH-512", "com.nets.kcmv.digest.LSH512Digest");
        // MACs
        this.put("Mac.HMAC-SHA256", "com.nets.kcmv.mac.HMACSHA256");
        this.put("Mac.CMAC-ARIA", "com.nets.kcmv.mac.CMACARIA");
        // Random (DRBG)
        this.put("SecureRandom.CTRDRBG", "com.nets.kcmv.drbg.CTRDRBG");
        this.put("SecureRandom.HASHDRBG", "com.nets.kcmv.drbg.HASHDRBG");
        // Public Key
        this.put("Cipher.RSA", "com.nets.kcmv.cipher.RSAEngine");
        this.put("Signature.RSASSA-PSS", "com.nets.kcmv.signature.RSASSAPSS");
        this.put("KeyPairGenerator.RSA", "com.nets.kcmv.keygen.RSAKeyPairGenerator");
        // 기타 Alias 예시
        this.put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        this.put("Alg.Alias.MessageDigest.sha256", "SHA-256");
        this.put("Alg.Alias.Cipher.ARIA", "ARIA");
        this.put("Alg.Alias.Mac.HMACSHA256", "HMAC-SHA256");
    }

    /**
     * Provider 설치 메소드
     */
    public static void installProvider() {
        if (providerInstalled) return;
        Security.addProvider(new NetsCryptoProvider());
        providerInstalled = true;
    }

    /**
     * Provider 제거 메소드
     */
    public static void removeProvider() {
        Security.removeProvider(PROVIDER_NAME);
        providerInstalled = false;
    }

    /**
     * (Optional) 자가 테스트 메소드
     */
    public static boolean selfTest() {
        // 여기서 실제 알고리즘별 테스트 코드 연동
        // ARIA, SHA256 등 각 암호 클래스의 Known Answer Test 등
        selfTested = true;
        return selfTested;
    }

    /**
     * Provider 설치 후 시스템 정보 출력 (디버깅 용)
     */
    public static void printProviderInfo() {
        Provider provider = Security.getProvider(PROVIDER_NAME);
        if (provider != null) {
            System.out.println("Provider Name: " + provider.getName());
            System.out.println("Provider Version: " + provider.getVersion());
            System.out.println("Provider Info: " + provider.getInfo());
            Enumeration<?> e = provider.propertyNames();
            while (e.hasMoreElements()) {
                String key = (String) e.nextElement();
                System.out.println(key + " = " + provider.getProperty(key));
            }
        }
    }
}
