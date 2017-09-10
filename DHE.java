
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

class DHE {
    static SecureRandom sr = null;
    final int keysize = 512;
    final int ARBITRARY_CONSTANT = 80;
    final int RADIX = 32;
    private DHKey key;
    private BigInteger x;
    private BigInteger x_pub;
    private BigInteger s_secret;

    DHE(DHKey dHKey) {
        this.key = dHKey;
        if (sr == null) {
            sr = new SecureRandom();
        }
        System.out.println("DHKey: g=" + this.key.g.toString() + " n=" + this.key.p.toString());
        this.x = new BigInteger(512, sr);
        this.x_pub = this.key.g.modPow(this.x, this.key.p);
        this.s_secret = BigInteger.valueOf(0);
    }

    DHE() {
        if (sr == null) {
            sr = new SecureRandom();
        }
        this.key = this.MakeKey(512, 80);
        this.x = new BigInteger(512, sr);
        this.x_pub = this.key.g.modPow(this.x, this.key.p);
        this.s_secret = BigInteger.valueOf(0);
        System.out.println("Done");
    }

    DHKey getKeyObject() {
        return this.key;
    }

    public String getExchangeKey() {
        return this.x_pub.toString(32);
    }

    public boolean setExchangeKey(String string) {
        try {
            BigInteger bigInteger = new BigInteger(string, 32);
            this.s_secret = bigInteger.modPow(this.x, this.key.p);
            return true;
        }
        catch (NumberFormatException var2_3) {
            System.err.println("Malformed DH Key");
            return false;
        }
    }

    BigInteger getSharedKey() {
        return this.s_secret;
    }

    private DHKey MakeKey(int n, int n2) {
        BigInteger bigInteger = BigInteger.valueOf(1);
        BigInteger bigInteger2 = BigInteger.valueOf(2);
        BigInteger bigInteger3 = BigInteger.valueOf(-1);
        BigInteger bigInteger4 = null;
        BigInteger bigInteger5 = null;
        BigInteger bigInteger6 = null;
        int n3 = 0;
        System.out.println("Initializing DHE ");
        System.out.print("Looking for a suitable n: ");
        boolean bl = false;
        do {
            if ((bigInteger6 = (bigInteger4 = new BigInteger(n, n2, sr)).subtract(bigInteger).divide(bigInteger2)).isProbablePrime(n2)) {
                bl = true;
            }
            System.out.print("" + ++n3 + " ");
        } while (!bl);
        System.out.println("\nFound " + bigInteger4.toString(32));
        bl = false;
        System.out.print("Looking for a suitable g: ");
        n3 = 0;
        BigInteger bigInteger7 = bigInteger3.mod(bigInteger4);
        do {
            if ((bigInteger5 = new BigInteger(n - 2, sr)).compareTo(bigInteger7) == 0 || bigInteger5.compareTo(bigInteger5.modPow(bigInteger6, bigInteger7)) == 0) {
                // empty if block
            }
            bl = true;
            System.out.print("" + ++n3 + " ");
        } while (!bl);
        return new DHKey(bigInteger4, bigInteger5, "DHE $Revision: 1.1 $/512");
    }

    public String toString() {
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append("Secret Key(x): " + this.x.toString(32) + "\n");
        stringBuffer.append("Public Key(X): " + this.x_pub.toString(32) + "\n");
        stringBuffer.append("Shared Key   : " + this.s_secret.toString(32));
        return stringBuffer.toString();
    }
}