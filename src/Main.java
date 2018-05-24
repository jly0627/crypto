import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Test driver for cSHAKE256 and KMACXOF256.
 *
 * @author Markku-Juhani Saarinen (original Keccak and SHAKE implementation in C)
 * @author Paulo S. L. M. Barreto (Java version, cSHAKE, KMACXOF)
 * @author Jake Yang (console UI)
 */
public class Main {
    private static int test_hexdigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return  ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return  ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return  ch - 'a' + 10;
        return -1;
    }

    private static int test_readhex(byte[] buf, String str, int maxbytes) {
        int i, h, l;

        for (i = 0; i < maxbytes; i++) {
            h = test_hexdigit(str.charAt(2*i));
            if (h < 0) {
                return i;
            }
            l = test_hexdigit(str.charAt(2*i + 1));
            if (l < 0) {
                return i;
            }
            buf[i] = (byte)((h << 4) + l);
        }
        return i;
    }

    private static int memcmp(byte[] a, byte[] b, int len) {
        for (int i = 0; i < len; i++) {
            if (a[i] != b[i]) {
                return a[i] - b[i];
            }
        }
        return 0;
    }

    private static int test_shake() {
        // Test vectors have bytes 480..511 of XOF output for given inputs.
        // From http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing

        String[] testhex = new String[] {
            // SHAKE256, message of length 0
            "AB0BAE316339894304E35877B0C28A9B1FD166C796B9CC258A064A8F57E27F2A",
            // SHAKE256, 1600-bit test pattern
            "6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB"
        };

        SHAKE shake = new SHAKE();
        byte[] buf = new byte[32], ref = new byte[32];

        int fails = 0;

        for (int i = 0; i < testhex.length; i++) {

            shake.init256();

            if (i >= 1) {   // 1600-bit test pattern
                Arrays.fill(buf, 0, 20, (byte)0xA3);
                for (int j = 0; j < 200; j += 20) {
                    shake.update(buf, 20);
                }
            }

            shake.xof();  // switch to extensible output

            for (int j = 0; j < 512; j += 32) { // output: discard bytes 0..479 (test only last 32 bytes)
                shake.out(buf, 32);
            }

            // compare to reference
            test_readhex(ref, testhex[i], ref.length);
            if (memcmp(buf, ref, 32) != 0) {
                System.out.println("[" + i + "] SHAKE256, len " + (i >= 1 ? 1600 : 0) + " test FAILED.");
                fails++;
            }
        }

        return fails;
    }

    /**
     * Convert an ASCII string to a byte array.
     * @param s string to convert to a byte array
     * @return  s converted to a byte array (all characters must be in range [0..255])
     */
    static byte[] asciiStringToByteArray(String s) {
        byte[] val = new byte[s.length()];
        for (int i = 0; i < val.length; i++) {
            char c = s.charAt(i);
            if (c >= 256) {
                throw new RuntimeException("Non-ASCII character found");
            }
            val[i] = (byte)c;
        }
        return val;
    }

    static String byteToHex(byte c) {
        String hex = "0123456789ABCDEF";
        String val = "";
        val += hex.charAt(((int)c >>> 4) & 0xF); val += hex.charAt((int)c & 0xF);
        return val;
    }

    private static void test_cshake256() {
        byte[] X_sample3 = new byte[] {(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03};
        byte[] X_sample4 = new byte[200];
        for (int i = 0; i < X_sample4.length; i++) {
            X_sample4[i] = (byte)i;
        }
        byte[] out_sample3 = new byte[] {
            (byte)0xD0, (byte)0x08, (byte)0x82, (byte)0x8E, (byte)0x2B, (byte)0x80, (byte)0xAC, (byte)0x9D, (byte)0x22, (byte)0x18, (byte)0xFF, (byte)0xEE, (byte)0x1D, (byte)0x07, (byte)0x0C, (byte)0x48,
            (byte)0xB8, (byte)0xE4, (byte)0xC8, (byte)0x7B, (byte)0xFF, (byte)0x32, (byte)0xC9, (byte)0x69, (byte)0x9D, (byte)0x5B, (byte)0x68, (byte)0x96, (byte)0xEE, (byte)0xE0, (byte)0xED, (byte)0xD1,
            (byte)0x64, (byte)0x02, (byte)0x0E, (byte)0x2B, (byte)0xE0, (byte)0x56, (byte)0x08, (byte)0x58, (byte)0xD9, (byte)0xC0, (byte)0x0C, (byte)0x03, (byte)0x7E, (byte)0x34, (byte)0xA9, (byte)0x69,
            (byte)0x37, (byte)0xC5, (byte)0x61, (byte)0xA7, (byte)0x4C, (byte)0x41, (byte)0x2B, (byte)0xB4, (byte)0xC7, (byte)0x46, (byte)0x46, (byte)0x95, (byte)0x27, (byte)0x28, (byte)0x1C, (byte)0x8C
        };
        byte[] out_sample4 = new byte[] {
            (byte)0x07, (byte)0xDC, (byte)0x27, (byte)0xB1, (byte)0x1E, (byte)0x51, (byte)0xFB, (byte)0xAC, (byte)0x75, (byte)0xBC, (byte)0x7B, (byte)0x3C, (byte)0x1D, (byte)0x98, (byte)0x3E, (byte)0x8B,
            (byte)0x4B, (byte)0x85, (byte)0xFB, (byte)0x1D, (byte)0xEF, (byte)0xAF, (byte)0x21, (byte)0x89, (byte)0x12, (byte)0xAC, (byte)0x86, (byte)0x43, (byte)0x02, (byte)0x73, (byte)0x09, (byte)0x17,
            (byte)0x27, (byte)0xF4, (byte)0x2B, (byte)0x17, (byte)0xED, (byte)0x1D, (byte)0xF6, (byte)0x3E, (byte)0x8E, (byte)0xC1, (byte)0x18, (byte)0xF0, (byte)0x4B, (byte)0x23, (byte)0x63, (byte)0x3C,
            (byte)0x1D, (byte)0xFB, (byte)0x15, (byte)0x74, (byte)0xC8, (byte)0xFB, (byte)0x55, (byte)0xCB, (byte)0x45, (byte)0xDA, (byte)0x8E, (byte)0x25, (byte)0xAF, (byte)0xB0, (byte)0x92, (byte)0xBB
        };
        byte[] N = asciiStringToByteArray(""); // empty string
        /*
        System.out.println("encoding of N (length " + N.length + "):");
        for (int i = 0; i < N.length; i++) {
            System.out.print(byteToHex(N[i]));
        }
        System.out.println();
        //*/
        int L = 512;
        byte[] S = asciiStringToByteArray("Email Signature");
        /*
        System.out.println("string S: \"" + S + "\"");
        System.out.print("encoding of S (length " + S.length + "):");
        for (int i = 0; i < S.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(S[i]));
        }
        System.out.println();
        //*/
        byte[] val_sample3 = SHAKE.cSHAKE256(X_sample3, L, N, S);
        byte[] val_sample4 = SHAKE.cSHAKE256(X_sample4, L, N, S);

        /*
        System.out.print("cSHAKE256 sample 3 [" + val_sample3.length + " bytes]:");
        for (int i = 0; i < val_sample3.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample3[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample3, out_sample3)) {
            throw new RuntimeException("NIST sample 3 failure!");
        }
        /*
        System.out.print("cSHAKE256 sample 4 [" + val_sample4.length + " bytes]:");
        for (int i = 0; i < val_sample4.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample4[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample4, out_sample4)) {
            throw new RuntimeException("NIST sample 4 failure!");
        }
        System.out.println("NIST SP 800-185/cSHAKE256 Sample Tests OK!");
    }

    private static void test_kmacxof256() {
        int L = 512;
        byte[] K = new byte[32];
        for (int i = 0; i < K.length; i++) {
            K[i] = (byte)(i + 0x40);
        }
        byte[] S = asciiStringToByteArray("My Tagged Application");

        byte[] X_sample4 = new byte[] {(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03};
        byte[] X_sample5 = new byte[200];
        for (int i = 0; i < X_sample5.length; i++) {
            X_sample5[i] = (byte)i;
        }
        byte[] X_sample6 = X_sample5;

        byte[] out_sample4 = new byte[] {
                (byte)0x17, (byte)0x55, (byte)0x13, (byte)0x3F, (byte)0x15, (byte)0x34, (byte)0x75, (byte)0x2A, (byte)0xAD, (byte)0x07, (byte)0x48, (byte)0xF2, (byte)0xC7, (byte)0x06, (byte)0xFB, (byte)0x5C,
                (byte)0x78, (byte)0x45, (byte)0x12, (byte)0xCA, (byte)0xB8, (byte)0x35, (byte)0xCD, (byte)0x15, (byte)0x67, (byte)0x6B, (byte)0x16, (byte)0xC0, (byte)0xC6, (byte)0x64, (byte)0x7F, (byte)0xA9,
                (byte)0x6F, (byte)0xAA, (byte)0x7A, (byte)0xF6, (byte)0x34, (byte)0xA0, (byte)0xBF, (byte)0x8F, (byte)0xF6, (byte)0xDF, (byte)0x39, (byte)0x37, (byte)0x4F, (byte)0xA0, (byte)0x0F, (byte)0xAD,
                (byte)0x9A, (byte)0x39, (byte)0xE3, (byte)0x22, (byte)0xA7, (byte)0xC9, (byte)0x20, (byte)0x65, (byte)0xA6, (byte)0x4E, (byte)0xB1, (byte)0xFB, (byte)0x08, (byte)0x01, (byte)0xEB, (byte)0x2B
        };
        byte[] out_sample5 = new byte[] {
                (byte)0xFF, (byte)0x7B, (byte)0x17, (byte)0x1F, (byte)0x1E, (byte)0x8A, (byte)0x2B, (byte)0x24, (byte)0x68, (byte)0x3E, (byte)0xED, (byte)0x37, (byte)0x83, (byte)0x0E, (byte)0xE7, (byte)0x97,
                (byte)0x53, (byte)0x8B, (byte)0xA8, (byte)0xDC, (byte)0x56, (byte)0x3F, (byte)0x6D, (byte)0xA1, (byte)0xE6, (byte)0x67, (byte)0x39, (byte)0x1A, (byte)0x75, (byte)0xED, (byte)0xC0, (byte)0x2C,
                (byte)0xA6, (byte)0x33, (byte)0x07, (byte)0x9F, (byte)0x81, (byte)0xCE, (byte)0x12, (byte)0xA2, (byte)0x5F, (byte)0x45, (byte)0x61, (byte)0x5E, (byte)0xC8, (byte)0x99, (byte)0x72, (byte)0x03,
                (byte)0x1D, (byte)0x18, (byte)0x33, (byte)0x73, (byte)0x31, (byte)0xD2, (byte)0x4C, (byte)0xEB, (byte)0x8F, (byte)0x8C, (byte)0xA8, (byte)0xE6, (byte)0xA1, (byte)0x9F, (byte)0xD9, (byte)0x8B
        };
        byte[] out_sample6 = new byte[] {
                (byte)0xD5, (byte)0xBE, (byte)0x73, (byte)0x1C, (byte)0x95, (byte)0x4E, (byte)0xD7, (byte)0x73, (byte)0x28, (byte)0x46, (byte)0xBB, (byte)0x59, (byte)0xDB, (byte)0xE3, (byte)0xA8, (byte)0xE3,
                (byte)0x0F, (byte)0x83, (byte)0xE7, (byte)0x7A, (byte)0x4B, (byte)0xFF, (byte)0x44, (byte)0x59, (byte)0xF2, (byte)0xF1, (byte)0xC2, (byte)0xB4, (byte)0xEC, (byte)0xEB, (byte)0xB8, (byte)0xCE,
                (byte)0x67, (byte)0xBA, (byte)0x01, (byte)0xC6, (byte)0x2E, (byte)0x8A, (byte)0xB8, (byte)0x57, (byte)0x8D, (byte)0x2D, (byte)0x49, (byte)0x9B, (byte)0xD1, (byte)0xBB, (byte)0x27, (byte)0x67,
                (byte)0x68, (byte)0x78, (byte)0x11, (byte)0x90, (byte)0x02, (byte)0x0A, (byte)0x30, (byte)0x6A, (byte)0x97, (byte)0xDE, (byte)0x28, (byte)0x1D, (byte)0xCC, (byte)0x30, (byte)0x30, (byte)0x5D
        };
        byte[] val_sample4 = SHAKE.KMACXOF256(K, X_sample4, L, S);
        byte[] val_sample5 = SHAKE.KMACXOF256(K, X_sample5, L, null);
        byte[] val_sample6 = SHAKE.KMACXOF256(K, X_sample6, L, S);

        /*
        System.out.print("KMACXOF256 sample 4 [" + val_sample4.length + " bytes]:");
        for (int i = 0; i < val_sample4.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample4[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample4, out_sample4)) {
            throw new RuntimeException("NIST sample 4 failure!");
        }
        /*
        System.out.print("KMACXOF256 sample 5 [" + val_sample5.length + " bytes]:");
        for (int i = 0; i < val_sample5.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample5[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample5, out_sample5)) {
            throw new RuntimeException("NIST sample 5 failure!");
        }
        /*
        System.out.print("KMACXOF256 sample 6 [" + val_sample6.length + " bytes]:");
        for (int i = 0; i < val_sample6.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(val_sample6[i]));
        }
        System.out.println();
        //*/
        if (!Arrays.equals(val_sample6, out_sample6)) {
            throw new RuntimeException("NIST sample 6 failure!");
        }
        System.out.println("NIST SP 800-185/KMACXOF256 Sample Tests OK!");
    }
    
    private static void printHex(byte[] hash) {
        for (int i = 0; i < hash.length; i++) {
            if ((i & 15) == 0) {
                System.out.print("\n    ");
            } else {
                System.out.print(" ");
            }
            System.out.print(byteToHex(hash[i]));
        }
        System.out.println();
    }
    
    private static String byteArrayToHexString(byte[] theBytes) {
        String hex = "";
    	for (int i = 0; i < theBytes.length; i++) {
            hex += byteToHex(theBytes[i]);
        }
        return hex;
    }
    
    private static byte[][] split(byte[] toSplit) {
    	byte[] a = new byte[64];
    	byte[] b = new byte[64];
    	for (int i = 0; i < toSplit.length; i+=2) {
    		a[i/2] = toSplit[i];
    		b[i/2] = toSplit[i+1];
    	}
    	byte[][] toReturn = new byte[2][];
    	toReturn[0] = a;
    	toReturn[1] = b;
    	return toReturn;
    }
    
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static void main(String[] args) throws IOException {
//        if (test_shake() == 0) {
//            System.out.println("FIPS 202/SHAKE256 Self-Tests OK!");
//        }
//        test_cshake256();
//        test_kmacxof256();
    	@SuppressWarnings("resource")
		Scanner input = new Scanner(System.in);
    	boolean loop = true;
    	while (loop) {
    		System.out.println();
			System.out.println("Select an option: ");
			System.out.println("(1) Compute plain cryptographic hash from a given file.");
			System.out.println("(2) Compute plain cryptographic hash from user input.");
			System.out.println("(3) Encrypt given data file symmetrically under given passphrase.");
			System.out.println("(4) Decrypt given symmetric cryptogram under given passphrase.");
			System.out.println();
			String choice = input.next();
			while (!choice.equals("1") && !choice.equals("2") && !choice.equals("3") && !choice.equals("4") && !choice.equals("5")) {
				System.out.println("Not a valid option.");
				choice = input.next();
			}
			// Part 1
			if (choice.equals("1") || choice.equals("2")) {
				byte[] X = null;
				if (choice.equals("1")) {
					System.out.println("Enter the filename:");
					X = Files.readAllBytes(Paths.get(input.next()));
				} else {
					System.out.println("Enter a string to hash:");
					X = asciiStringToByteArray(input.next());
				}
				System.out.println("Enter a desired output length (in bits): ");
				int L = input.nextInt();
				System.out.println("Enter a customization string: ");
				input.nextLine();
				byte[] S = asciiStringToByteArray(input.nextLine());
				System.out.print("Hash of input: ");
		        byte[] K = new byte[32];
		        for (int i = 0; i < K.length; i++) {
		            K[i] = (byte)(i + 0x40);
		        }
				byte[] hash = SHAKE.KMACXOF256(K, X, L, S);
				printHex(hash);   
			// Part 2
			} else if (choice.equals("3")) {
				System.out.println("Enter the filename:");
				byte[] X = Files.readAllBytes(Paths.get(input.next()));
				
				// creating pw, z, z || pw
				System.out.println("Enter a passphrase:");
				input.nextLine();
				byte[] pw = asciiStringToByteArray(input.nextLine());
				byte[] z = new BigInteger(511, new SecureRandom()).toByteArray();
				byte[] zpw = new byte[z.length + pw.length];
				System.arraycopy(z, 0, zpw, 0, z.length);
				System.arraycopy(pw, 0, zpw, z.length, pw.length);
				
				// getting c and t
				byte[][] keka = split(SHAKE.KMACXOF256(zpw, new byte[0], 1024, asciiStringToByteArray("S")));
				byte[] c = SHAKE.KMACXOF256(keka[0], new byte[0], X.length * 8, asciiStringToByteArray("SKE"));
				for (int i = 0; i < X.length; i++) {
					c[i] = (byte) (c[i] ^ X[i]);
				}
				byte[] t = SHAKE.KMACXOF256(keka[1], X, 512, asciiStringToByteArray("SKA"));
				
				// saving as a file
				System.out.println("Save cryptogram as: ");
				File file = new File(input.nextLine());
				FileWriter writer = new FileWriter(file);
				writer.write(byteArrayToHexString(z) + "\n");
				writer.write(byteArrayToHexString(c) + "\n");
				writer.write(byteArrayToHexString(t));
				writer.close();
				System.out.println("Saved!");
				
			} else if (choice.equals("4")) {
				
				// get z, c, t from file
				System.out.println("Enter the filename: ");
				input.nextLine();
				File file = new File(input.nextLine());
				Scanner fileScanner = new Scanner(file);
				byte[] z = hexStringToByteArray(fileScanner.nextLine());
				byte[] c = hexStringToByteArray(fileScanner.nextLine());
				byte[] t = hexStringToByteArray(fileScanner.nextLine());
				fileScanner.close();
				
				// authenticate and get message
				System.out.println("Enter a passphrase:");
				byte[] pw = asciiStringToByteArray(input.nextLine());
				byte[] zpw = new byte[z.length + pw.length];
				System.arraycopy(z, 0, zpw, 0, z.length);
				System.arraycopy(pw, 0, zpw, z.length, pw.length);
				byte[][] keka = split(SHAKE.KMACXOF256(zpw, new byte[0], 1024, asciiStringToByteArray("S")));
				byte[] m = SHAKE.KMACXOF256(keka[0], new byte[0], c.length * 8, asciiStringToByteArray("SKE"));
				byte[] tPrime = SHAKE.KMACXOF256(keka[1], m, 512, asciiStringToByteArray("SKA"));
				if (Arrays.equals(tPrime, t)) {
					System.out.println("Message is: ");
					System.out.println(new String(m));
				} else {
					System.out.println("Incorrect passphrase");
				}
				System.out.println(byteArrayToHexString(m));
				
			}
			
			System.out.println();
	        System.out.println("(1) Return to menu\n(Anything else) Exit");
	        if (!input.next().equals("1")) {
	        	loop = false;
	        }
    	}
    }

}
