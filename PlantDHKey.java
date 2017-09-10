import java.util.Date;
import java.security.*;
import java.math.*;
import java.io.*;

/*
 * This object is used for Public Key Exchange.
 * The Crypto routines require it.  I haven't put the heavy
 * duty methods in here because I want it to stay small
 */

class DHKey implements Serializable {
    BigInteger p, g;    /* These two make up the public Key */

    String Description;
    Date created;

    DHKey (BigInteger P, BigInteger G, String what) {
        p = P;
        g = G;

        Description = what;
        created = new Date();
    }

    /* You may wish to customize the following */
    public String toString() {
        StringBuffer scratch = new StringBuffer();
        scratch.append("Public Key(p): " + p.toString(32) + "\n" );
        scratch.append("Public Key(g): " + g.toString(32) + "\n" );
        scratch.append("Description: "   + Description  + "\n" );
        scratch.append("Created: "       + created );
        return scratch.toString();
    }
}

public class PlantDHKey {
    public static void main (String arg[]) {
        try {
            BigInteger p = new BigInteger("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",16);
            BigInteger g = new BigInteger("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",16);
            DHKey key = new DHKey(p,g,"C6053 DH key");
            FileOutputStream fos = new FileOutputStream("DHKey");
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(key);
        } catch (Exception e) {
            System.out.println("Whoops!");
        }
    }
}
