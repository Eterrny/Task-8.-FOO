import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;

public class Counter {
    private final BigInteger privateKey;
    private final BigInteger publicKey;

    private ArrayList<String> encChoices = new ArrayList<>();
    private ArrayList<Integer> results = new ArrayList<>();

    private BigInteger adminKey;

    public Counter(int electedCount) {
        RSAService service = new RSAService();
        this.privateKey = service.getPrivateKey();
        this.publicKey = service.getPublicKey();
        for (int i = 0; i < electedCount; ++i) {
            results.add(0);
        }
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public ArrayList<String> getEncChoices() {
        return encChoices;
    }

    public void setAdminKey(BigInteger adminKey) {
        this.adminKey = adminKey;
    }

    public void takeEncChoiceSigned(String encChoice, BigInteger encChoiceSHA, BigInteger encChoiceSigned, BigInteger n) {
        if (!checkMessage(encChoiceSHA, encChoiceSigned, n)) {
            System.out.println("Счетчик получил бюллетень, которую регистратор не подписывал.");
            return;
        }
        encChoices.add(encChoice);
    }

    private boolean checkMessage(BigInteger encChoice, BigInteger encChoiceSigned, BigInteger n) {
//        System.out.println("check: " + encChoiceSigned.modPow(adminKey, n));
        return encChoice.equals(encChoiceSigned.modPow(adminKey, n));
    }

    public void decryptAndUpdateResults(int vIndex, SecretKey aesKey, IvParameterSpec iv) {
        if (vIndex == -1) {
            System.out.println("Голосующий не смог найти себя в списке.");
            return;
        }
        Integer choice = null;
        try {
            choice = Integer.parseInt(AESService.decrypt(encChoices.get(vIndex), aesKey, iv)) - 1;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Ошибка в расшифровании одного из голосов: " + e.getMessage());
        } catch (NumberFormatException e) {
            System.out.println("В качестве голоса получено не число.\n" + e.getMessage());
        }
        if (choice == null) {
            return;
        }
        results.set(choice, results.get(choice) + 1);
    }

    public void publishResults() {
        int winner = findWinner();
        System.out.println("Результаты голосования:");
        for (int i = 0; i < results.size(); ++i) {
            System.out.println("Избираемый #" + (i + 1) + ": " + results.get(i));
        }
        System.out.println("\nРезультаты голосования в процентах:");
        for (int i = 0; i < results.size(); ++i) {
            System.out.println("Избираемый #" + (i + 1) + ": " + String.format("%.2f", (double)results.get(i) / encChoices.size() * 100, 2) + "%");
        }
        if (drawn(results.get(winner - 1))){
            System.out.println("По итогом выборов победитель не определен. Необходимо провести повторное голосавание.");
        } else {
            System.out.println("\nПобедитель выборов: избираемый #" + (winner));
        }
    }

    private boolean drawn(Integer max) {
        int cnt = 0;
        for(int res : results) {
            if (res == max) {
                ++cnt;
            }
        }
        return cnt != 1;
    }

    private int findWinner() {
        int max = 0;
        int winner = -1;
        for(int i = 0; i < results.size(); ++i){
            if (results.get(i) > max) {
                max = results.get(i);
                winner = i + 1;
            }
        }
        return winner;
    }
}
