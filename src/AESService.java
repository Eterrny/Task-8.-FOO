import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESService {
    private final SecretKey publicKey;
    private final IvParameterSpec iv;
    private final int keyLength = 128;

    private static final String algorithm = "AES/CBC/PKCS5Padding";

    public SecretKey getPublicKey() {
        return publicKey;
    }

    public IvParameterSpec getIv() {
        return iv;
    }

    public AESService() throws NoSuchAlgorithmException {
        this.publicKey = generateKey(this.keyLength);
        this.iv = generateIv();
    }

    public static SecretKey generateKey(int keyLength) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keyLength);
        return keyGenerator.generateKey();
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String input, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    public static String convertSecretKeyToString(SecretKey secretKey) {
        byte[] rawData = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(rawData);
    }

    public static SecretKey convertStringToSecretKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
