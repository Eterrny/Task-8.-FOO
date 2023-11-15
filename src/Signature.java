import java.math.BigInteger;

public class Signature {
    private BigInteger S1, S2;
    private final BigInteger h, n;

    public Signature(BigInteger S1, BigInteger S2, BigInteger h, BigInteger n) {
        this.S1 = S1;
        this.S2 = S2;
        this.h = h;
        this.n = n;
    }

    public BigInteger getS1() {
        return S1;
    }

    public BigInteger getS2() {
        return S2;
    }

    public BigInteger getH() {
        return h;
    }

    public BigInteger getN() {
        return n;
    }

    @Override
    public String toString() {
        return "(" + S1 + ", " + S2 + ")";
    }

    public void setS1(BigInteger s1){
        this.S1 = s1;
    }
}
