import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Random;
import java.util.StringTokenizer;

public class ZKPMain {

	public BigInteger sqr = new BigInteger("2", 10);
	public BigInteger v;
	public BigInteger s;
	public BigInteger n;
	public int rounds;
	public BigInteger[] R;
	public int[] A;
	public int subsetAsize;
	public BigInteger[] K;
	public BigInteger[] J;

	public ZKPMain() {
		try {
			// Generate a 512-bit RSA key pair
			KeyFactory kf = KeyFactory.getInstance("RSA");
			KeyPairGenerator kpgRSA = KeyPairGenerator.getInstance("RSA");

			kpgRSA.initialize(512);
			KeyPair kpKeyPair = kpgRSA.genKeyPair();
			RSAPublicKeySpec x = (RSAPublicKeySpec) kf.getKeySpec(kpKeyPair.getPublic(), RSAPublicKeySpec.class);
			n = x.getModulus();

			// Returns a random 512 bit BigInteger
			s = new BigInteger(512, new SecureRandom());

			// Now we have our public value
			v = s.pow(2).mod(n);

			System.out.println("Value of n,s and v is"+n+"-"+s+"-"+v);
		} catch (NoSuchAlgorithmException e) {
		} catch (InvalidKeySpecException e) {
		}
	}

	public String getPublicKey() {
		return "PUBLIC_KEY " + v + " " + n;
	}

	public void saveRounds(String msg) {
		// StringTokenizer t = new StringTokenizer(msg, "\\s");
		// t.nextToken();
		// rounds = Integer.parseInt(t.nextToken());
		rounds = Integer.parseInt(msg);
	}

	public String getAuthorizeSet() {
		Random rnd = new Random();
		R = new BigInteger[rounds];
		String msg = "AUTHORIZE_SET ";
		for (int i = 0; i < rounds; i++) {
			R[i] = new BigInteger(256, rnd);
			msg = msg.concat(" ").concat(R[i].modPow(sqr, n).toString());
		}
		System.out.println(msg);
		return msg;
	}

	public void saveSubsetA(String msg) {
		StringTokenizer t = new StringTokenizer(msg, " ");
		// subsetAsize = t.countTokens()-1;
		subsetAsize = t.countTokens();
		A = new int[subsetAsize];
//		t.nextToken();
		for (int i = 0; i < subsetAsize; i++) {

			A[i] = Integer.parseInt(t.nextToken());
		}
	}

	public String getSubsetK() {
		String msg = "SUBSET_K ";
		for (int i = 0; i < subsetAsize; i++) {
			msg += R[A[i]].multiply(s).modPow(sqr, n) + " ";
		}
		return msg;
	}

	public String getSubsetJ() {
		String msg = "SUBSET_J ";
		for (int i = 0; i < rounds; i++) {
			int j = 0;
			for (; j < subsetAsize; j++)
				if (A[j] == i)
					break;
			if (j != subsetAsize)
				continue;
			msg += R[i].modPow(sqr, n) + " ";
		}
		return msg;
	}

}
