import javax.crypto.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAService {
//    private final PublicKey publicKey;
//    private final PrivateKey privateKey;
    private final int keySize = 16;
    private BigInteger p, q, n, privateKey, publicKey;

    private static final String algorithm = "RSA";

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public BigInteger getN() {
        return n;
    }

    public RSAService() {
        SecureRandom rnd = new SecureRandom();
        int size = keySize / 2;
        this.p = BigInteger.probablePrime(size, rnd);
        this.q = BigInteger.probablePrime(size, rnd);
        while (p.equals(q)){
            q = BigInteger.probablePrime(size, rnd);
        }
        this.n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        do {
            this.publicKey = new BigInteger(phi.bitLength(), rnd).mod(phi);
        } while(!this.publicKey.gcd(phi).equals(BigInteger.ONE));
        this.privateKey = publicKey.modInverse(phi);
//        KeyPairGenerator generator = null;
//        try {
//            generator = KeyPairGenerator.getInstance("RSA");
//        } catch (NoSuchAlgorithmException e) {
//            System.out.println(e.getMessage());
//            System.exit(1);
//        }
//        generator.initialize(keySize);
//        KeyPair pair = generator.generateKeyPair();
//        this.publicKey = pair.getPublic();
//        this.privateKey = pair.getPrivate();
    }

    public static String encrypt(String input, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (NoSuchPaddingException e) {
            System.out.println(e.getMessage());
        } catch (IllegalBlockSizeException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (NoSuchPaddingException e) {
            System.out.println(e.getMessage());
        } catch (IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public static String convertPublicKeyToString(PublicKey secretKey) {
        byte[] rawData = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(rawData);
    }

    public static String convertPrivateKeyToString(PrivateKey secretKey) {
        byte[] rawData = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(rawData);
    }

    public static PrivateKey convertStringToPrivateKey(String encodedKey) {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new PKCS8EncodedKeySpec(decodedKey);
            return keyFactory.generatePrivate(publicKeySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public static PublicKey convertStringToPublicKey(String encodedKey) {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedKey);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return null;
    }
}
