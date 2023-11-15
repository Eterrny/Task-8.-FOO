import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Random;

public class Voter {
    private final BigInteger privateKey;
    private final BigInteger publicKey;
    private BigInteger counterKey;
    private BigInteger adminKey;
    private SecretKey aesKey;
    private IvParameterSpec iv;
    private BigInteger n;
    private BigInteger r;
    private final int id;
    private int choice;
    private String encChoice;
    private BigInteger encChoiceSHA, encChoiceBlind, encChoiceBlindSigned, encChoiceSigned;
    private Signature s;
    private BigInteger k, h; // для подписи

    public Voter(int id) {
        RSAService service = new RSAService();
        this.privateKey = service.getPrivateKey();
        this.publicKey = service.getPublicKey();
        this.id = id;
//        SecureRandom rnd = new SecureRandom();
//        this.n = BigInteger.probablePrime(30, rnd);
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public int getId() {
        return id;
    }

    public BigInteger getEncChoiceSHA() {
        return encChoiceSHA;
    }

    public String getEncChoice() {
        return encChoice;
    }

    public Signature getSignature() {
        return s;
    }

    public BigInteger getEncChoiceBlind() {
        return encChoiceBlind;
    }

    public BigInteger getEncChoiceBlindSigned() {
        return encChoiceBlindSigned;
    }

    public BigInteger getEncChoiceSigned() {
        return encChoiceSigned;
    }

    public BigInteger getN() {
        return n;
    }

    public SecretKey getAesKey() {
        return aesKey;
    }

    public IvParameterSpec getIv() {
        return iv;
    }

    public int getChoice() {
        return choice;
    }

    public BigInteger getR() {
        return r;
    }

    public void setCounterKey(BigInteger counterKey) {
        this.counterKey = counterKey;
    }

    public void setAdminKey(BigInteger adminKey) {
        this.adminKey = adminKey;
    }

    public void setEncChoiceBlindSigned(BigInteger encChoiceBlindSigned) {
        this.encChoiceBlindSigned = encChoiceBlindSigned;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public void generateSymmetricKey() {
        try {
            AESService service = new AESService();
            this.aesKey = service.getPublicKey();
            this.iv = service.getIv();
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
    }

    public void makeChoiceAndEncrypt(ArrayList<Integer> elected) {
        Random rnd = new Random();
        this.choice = elected.get(rnd.nextInt(elected.size()));
        try {
            this.encChoice = AESService.encrypt(String.valueOf(choice), aesKey, iv);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException |
                 InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
        this.encChoiceSHA = SHA.sha(encChoice).mod(n);
    }


    public void blindAndSign() {
        SecureRandom rnd = new SecureRandom();
        this.r = new BigInteger(n.bitLength(), rnd).mod(n);
        while (!r.gcd(n).equals(BigInteger.ONE)) {
            this.r = new BigInteger(n.bitLength(), rnd).mod(n);
        }
        encChoiceBlind = encChoiceSHA.multiply(r.modPow(adminKey, n)).mod(n);
        this.signMessage();
    }

    public void signMessage() {
        if (encChoiceBlind == null) {
            System.out.println("Попытка подписать сообщение, которого не существует.");
            System.exit(1);
        }
        SecureRandom rnd = new SecureRandom();
        this.k = new BigInteger(n.bitLength(), rnd).mod(n);
        while (!k.gcd(n).equals(BigInteger.ONE)) {
            this.k = new BigInteger(n.bitLength(), rnd).mod(n);
        }
        BigInteger invK = k.modInverse(n);
        this.h = invK.multiply(invK).negate().mod(n);
        BigInteger invTwo = BigInteger.TWO.modInverse(n);
        //BigInteger r = new BigInteger(n.bitLength(), rnd).mod(n);
        BigInteger invR = r.modInverse(n);
        this.s = new Signature(
                invTwo.multiply(encChoiceBlind.multiply(invR).add(r)).mod(n),
                k.multiply(invTwo).multiply(encChoiceBlind.multiply(invR).subtract(r)).mod(n),
                h, n);
    }

    public void unblind() {
        this.encChoiceSigned = this.encChoiceBlindSigned.multiply(r.modInverse(n)).mod(n);
    }

    public int findInList(ArrayList<String> encChoices) {
        for (int i = 0; i < encChoices.size(); ++i) {
            if (encChoices.get(i).equals(encChoice)){
                return i;
            }
        }
        return -1;
    }
}
