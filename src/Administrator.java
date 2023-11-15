import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class Administrator {
    private final BigInteger privateKey, publicKey, n;
//    private final BigInteger privateKeyInt, publicKeyInt;
    private BigInteger counterKey;

    // private HashMap<PublicKey, Integer> voters = new HashMap<>();
    private ArrayList<VoterInfo> voters = new ArrayList<>();
    private Set<Integer> votersWithAccess = new HashSet<>();
    private int accessCnt = 0;


    private static class VoterInfo {
        public BigInteger key;
        public int id;

        public VoterInfo(BigInteger key, int id) {
            this.key = key;
            this.id = id;
        }
    }

    public Administrator() {
        RSAService service = new RSAService();
        this.privateKey = service.getPrivateKey();
        this.publicKey = service.getPublicKey();
        this.n = service.getN();
//        this.privateKeyInt = SHA.sha(RSAService.convertPrivateKeyToString(privateKey));
//        this.publicKeyInt = SHA.sha(RSAService.convertPublicKeyToString(publicKey));
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getN() {
        return n;
    }

    //    public BigInteger getPublicKeyInt() {
//        return publicKeyInt;
//    }

    //    public HashMap<PublicKey, Integer> getVoters() {
//        return voters;
//    }

    public void setCounterKey(BigInteger counterKey) {
        this.counterKey = counterKey;
    }

    public void registrateVoter(Voter voter) {
        if (votersWithAccess != null && votersWithAccess.size() != 0) {
            if (votersWithAccess.contains(voter.getId())){
                voters.add(new VoterInfo(voter.getPublicKey(), voter.getId()));
                ++accessCnt;
            }
            return;
        }
        voters.add(new VoterInfo(voter.getPublicKey(), voter.getId()));
    }

    public String printListOfVoters() {
        String res = "[";
        for (int i = 0; i < voters.size(); ++i) {
            if (i != voters.size() - 1) {
                res += voters.get(i).id + ", ";
            } else {
                res += voters.get(i).id + "]";
            }
        }
        return res;
    }

    public BigInteger sendBallot(BigInteger encChoiceBlind, Signature signature, BigInteger publicKey) {
        if (!findVoter(publicKey) || !checkMessage(encChoiceBlind, signature)) {
            System.out.println("Администратор получил сообщение от нелегитимного голосующего.");
            return null;
        }
        return signBlind(encChoiceBlind, signature.getN());
    }

    private BigInteger signBlind(BigInteger encChoiceBlind, BigInteger n) {
        return encChoiceBlind.modPow(this.privateKey, n);
    }

    private boolean checkMessage(BigInteger encChoiceBlind, Signature s) {
        BigInteger s1 = s.getS1();
        BigInteger s2 = s.getS2();
        BigInteger check = s1.multiply(s1).add(s.getH().multiply(s2.multiply(s2))).mod(s.getN());
        //System.out.println("check: " + check);
        return check.equals(encChoiceBlind);
    }

    private boolean findVoter(BigInteger publicKey) {
        for (VoterInfo vi : voters) {
            if (vi.key.equals(publicKey)) {
                return true;
            }
        }
        //System.out.println("Не нашлось голосующего.");
        return false;
    }

    public void addVoterWithAccess(int index) {
        votersWithAccess.add(index);
    }

    public Set<Integer> getVotersWithAccess() {
        return votersWithAccess;
    }

    public ArrayList<VoterInfo> getVoters() {
        return voters;
    }
}
