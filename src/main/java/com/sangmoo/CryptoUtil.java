package com.sangmoo;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import org.mindrot.jbcrypt.BCrypt;
import com.lambdaworks.crypto.SCryptUtil;

public class CryptoUtil {

    private static final String AES_CBC_PADDING = "AES/CBC/PKCS5Padding";
    private static final String AES = "AES";
    private static final String UTF_8 = "UTF-8";

    // 🔐 AES CBC 암호화
    public static String encryptAES(String plainText, String key, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC_PADDING);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(UTF_8), AES);
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(UTF_8));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 🔓 AES CBC 복호화
    public static String decryptAES(String encryptedText, String key, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC_PADDING);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(UTF_8), AES);
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(UTF_8));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decoded = Base64.getDecoder().decode(encryptedText);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, UTF_8);
    }

    // 🔒 SHA256 해싱
    public static String hashSHA256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) hexString.append(String.format("%02x", b));
        return hexString.toString();
    }

    // 🔐 PBKDF2 해싱
    public static String hashPBKDF2(String password, String salt) throws Exception {
        int iterations = 65536;
        int keyLength = 128;
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(UTF_8), iterations, keyLength);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }

    // 🔐 bcrypt 해싱
    public static String hashBCrypt(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public static boolean verifyBCrypt(String password, String hashed) {
        return BCrypt.checkpw(password, hashed);
    }

    // 🔐 scrypt 해싱
    public static String hashSCrypt(String password) {
        return SCryptUtil.scrypt(password, 16384, 8, 1);
    }

    public static boolean verifySCrypt(String password, String hashed) {
        return SCryptUtil.check(password, hashed);
    }
}
