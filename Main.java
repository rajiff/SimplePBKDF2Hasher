import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;

import java.util.Map;
import java.math.BigInteger;

/** A really simple SimplePBKDF2 Encryption example.
 *
 */
class SimplePBKDF2Hasher {
  private static String bytesToHex(byte[] array) {
    BigInteger bi = new BigInteger(1, array);
    String hex = bi.toString(16);
    int paddingLength = array.length * 2 - hex.length();
    if (paddingLength > 0) {
      return String.format("%0" + paddingLength + "d", 0) + hex;
    } else {
      return hex;
    }
  }

  public static String gethashPBKDF2WithHmacSHA1(String privateKey, String inputStr) 
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    char[] chars = inputStr.toCharArray();
    byte[] salt = privateKey.getBytes();

    int iterations=1001;
    int dkLen=25; // derived key length

    PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, dkLen*8);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

    // Converting to Hex is essential
    return bytesToHex(skf.generateSecret(spec).getEncoded()).toUpperCase();
  }
}

class Main {
  public static void main(String[] args) {
    // System.out.println("Hello world!");
    try {
      String privateKey = "secret";
      String inputStr = "string_to_encrypt";

      System.out.println("Simple hash: " + SimplePBKDF2Hasher.gethashPBKDF2WithHmacSHA1(privateKey, inputStr));
    } catch (Exception ex) {
      System.out.println("Exception " + ex);
    }
  }
}