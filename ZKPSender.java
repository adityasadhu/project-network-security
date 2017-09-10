import java.math.BigInteger;
import java.util.StringTokenizer;

public class ZKPSender {

	public BigInteger v;
	public BigInteger n;
	public int rounds;
	public BigInteger[] RR;
	public boolean check;

	public void savePublicKey(String msg) {
		StringTokenizer t = new StringTokenizer(msg, " ");
		t.nextToken();
		t.nextToken();
		v = new BigInteger(t.nextToken());
		n = new BigInteger(t.nextToken());
	}

	public String getRounds(int rnds) {
		rounds = rnds;
		return "ROUNDS " + rnds;
	}

	public void saveAuthorizeSet(String msg) {
		StringTokenizer t = new StringTokenizer(msg, " ");
		t.nextToken();
		t.nextToken();
		RR = new BigInteger[rounds];
		for (int i = 0; i < rounds; i++) {
			RR[i] = new BigInteger(t.nextToken());
		}
	}

	public String getSubsetA() {
		String msg = "SUBSET_A ";
		for (int i = 0; i < rounds; i += 2)
			msg += i + " ";
		return msg;
	}

	public boolean checkSubsetK(String msg) {
		check = true;
		StringTokenizer t = new StringTokenizer(msg, " ");
		t.nextToken();
		t.nextToken();
		for (int i = 0; i < rounds; i += 2) {
			BigInteger a1 = RR[i].multiply(v).mod(n);
			BigInteger a2 = new BigInteger(t.nextToken());
			if (!a1.equals(a2)) {
				check = false;
				return false;
			}
		}
		return true;
	}

	public boolean checkSubsetJ(String msg) {
		StringTokenizer t = new StringTokenizer(msg, " ");
		t.nextToken();
		t.nextToken();
		for (int i = 1; i < rounds; i += 2) {
			BigInteger a1 = RR[i];
			BigInteger a2 = new BigInteger(t.nextToken());
			if (!a1.equals(a2)) {
				check = false;
				return false;
			}
		}
		return true;
	}

	public String response() {
		if (check)
			return "TRANSFER_REQUEST ACCEPT";
		else
			return "TRANSFER_REQUEST REJECT";
	}

}
