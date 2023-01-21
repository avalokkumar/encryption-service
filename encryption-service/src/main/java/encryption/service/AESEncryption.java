package encryption.service;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class uses "AES/CBC/PKCS7Padding" algorithm for encryption, and the "BC" provider for cryptographic operations.
 */
public class AESEncryption {

    private static final String ALGORITHM = "AES/CBC/PKCS7Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    /**
     * generates a new AES key using a KeyGenerator instance.
     *
     * @return
     * @throws Exception
     */
    public static byte[] generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, "BC");
        keyGenerator.init(KEY_SIZE, new SecureRandom());
        SecretKey key = keyGenerator.generateKey();
        return key.getEncoded();
    }

    /**
     * encrypts the given data using the given key and return the cipher text.
     *
     * @param key
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        Key aesKey = new SecretKeySpec(key, KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = cipher.getIV();
        byte[] cipherText = cipher.doFinal(data);
        byte[] result = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);
        return result;
    }

    /**
     * decrypts the given cipher text using the given key and return the original data.
     *
     * @param key
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] key, byte[] data) throws Exception {
        byte[] iv = new byte[16];
        System.arraycopy(data, 0, iv, 0, 16);
        byte[] cipherText = new byte[data.length - 16];
        System.arraycopy(data, 16, cipherText, 0, data.length - 16);

        Key aesKey = new SecretKeySpec(key, KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }
}
