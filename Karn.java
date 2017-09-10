import java.io.*;
import java.util.Date;
import java.math.BigInteger;
import java.security.*;

class Karn {
    final int RADIX=32;
    final int PADSIZE=40; // Plaintext buffer */

    private byte key[];
    private byte key_left[];
    private byte key_right[];

    static SecureRandom sr = null;  // This is expensive.  We only need one
    static MessageDigest md = null; // This will be shared.

    Karn (BigInteger bi) {
        if (sr == null) sr = new SecureRandom();
        key = bi.toByteArray();

        // Digest encryption needs keys split into two halves
        key_left =  new byte[key.length/2];
        key_right = new byte[key.length/2];

        for (int i = 0 ; i < key.length/2 ; i++) {
            key_left[i] = key[i];
            key_right[i] = key[i+key.length/2];
        }

        try {
            md = MessageDigest.getInstance("SHA");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Yow! NoSuchAlgorithmException. Abandon all hope");
        }
    }

    // Encrypt the string using the karn algorithm
    String encrypt(String plaintext) {
        byte[] plain_left, plain_right;
        byte[] ciph_left, ciph_right;
        byte[] digest;

        // These buffers are used for the encryption.
        byte input[] = StringToBytes(plaintext); // Pad the string

        plain_left =  new byte[PADSIZE/2];
        plain_right = new byte[PADSIZE/2];

        ciph_left =  new byte[PADSIZE/2];
        ciph_right =  new byte[PADSIZE/2];

        digest = new byte[PADSIZE/2];  // Temp storage for the hash

        // Our pointer into the workspace
        int cursor = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Guard Byte for the ciphertext
        out.write(42);

        while (cursor < input.length) {
            // Copy the next slab into the left and right
            for (int i=0 ; i < PADSIZE/2 ; i++) {
                plain_left[i] = input[cursor + i];
                plain_right[i] = input[cursor + PADSIZE/2 + i];
            }

            // Hash the left plaintext with the left key
            md.reset(); // Start the hash fresh
            md.update(plain_left);
            md.update(key_left);
            digest = md.digest(); // Get out the digest bits
            // XOR the digest with the right plaintext for the right c-text
            // Right half
            for (int i=0 ; i < PADSIZE/2 ; i++)
                ciph_right[i] = (byte)(digest[i] ^ plain_right[i]);

            // Now things get a little strange
            md.reset();
            md.update(ciph_right);
            md.update(key_right);
            digest = md.digest();
            for (int i=0 ; i < PADSIZE/2 ; i++)
                ciph_left[i] = (byte) (digest[i] ^ plain_left[i]);

            out.write(ciph_left,0,PADSIZE/2);
            out.write(ciph_right,0,PADSIZE/2);
            cursor += PADSIZE;
        }
        BigInteger bi_out = new BigInteger(out.toByteArray());
        return(bi_out.toString(RADIX));
    }

    // Decrypt the ciphertext by running Karn in reverse
    String decrypt(String ciphertext) {
        BigInteger bigInteger = new BigInteger(ciphertext, 32);
        byte[] input = bigInteger.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(input, 1, input.length - 1);
        input = out.toByteArray();
        byte[] ciph_left = new byte[20];
        byte[] ciph_right = new byte[20];
        byte[] plain_left = new byte[20];
        byte[] plain_right = new byte[20];
        byte[] digest = new byte[20];

        ByteArrayOutputStream out2 = new ByteArrayOutputStream();
        for (int i = 0; i < input.length; i += 40) {
            int n;
            for (n = 0; n < 20; ++n) {
                ciph_left[n] = input[i + n];
                ciph_right[n] = input[i + 20 + n];
            }
            md.reset();
            md.update(ciph_right);
            md.update(this.key_right);
            digest = md.digest();
            for (n = 0; n < 20; ++n) {
                plain_left[n] = (byte)(digest[n] ^ ciph_left[n]);
            }
            md.reset();
            md.update(plain_left);
            md.update(this.key_left);
            digest = md.digest();
            for (n = 0; n < 20; ++n) {
                plain_right[n] = (byte)(digest[n] ^ ciph_right[n]);
            }
            out2.write(plain_left, 0, 20);
            out2.write(plain_right, 0, 20);
        }
        String string2 = this.StripPadding(out2.toByteArray());
        return string2;
    }

    // Padding
    private byte[] StringToBytes(String input) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte scratch[];

        scratch = input.getBytes();
        int len = input.length();

        buffer.write(scratch,0,len);
        buffer.write(0);
        int len2=40-(len+1) % 40;
        scratch=new byte[len2];
        buffer.write(scratch,0,len2);
        return (buffer.toByteArray());
    }

    // Strip the header off the byte array and return the string
    private String StripPadding (byte input[]) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int i = 0;
        for (i=0; i < input.length && input[i] != 0; ++i) {
            buffer.write(input[i]);
        }
        return (new String(buffer.toByteArray()));
    }
}

