package encryption.service;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * A class that provides methods for performing DES encryption and decryption using the Bouncy Castle library
 */
public class DESEncryption {

    /**
     * The encryption algorithm to be used
     */
    private static final String ALGORITHM = "DES";
    /**
     * The key size in bits for the encryption algorithm
     */
    private static final int KEY_SIZE = 56;

    /**
     * Generates a new DES key
     * @return the generated key as a byte array
     * @throws Exception if there is an error generating the key
     */
    public static byte[] generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, "BC");
        keyGenerator.init(KEY_SIZE, new SecureRandom());
        SecretKey key = keyGenerator.generateKey();
        return key.getEncoded();
    }

    /**
     * Encrypts the given data using the given key
     * @param key the key to be used for encryption
     * @param data the data to be encrypted
     * @return the encrypted data as a byte array
     * @throws Exception if there is an error encrypting the data
     */
    public static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        Key desKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, desKey);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts the given data using the given key
     * @param key the key to be used for decryption
     * @param data the data to be decrypted
     * @return the decrypted data as a byte array
     * @throws Exception if there is an error decrypting the data
     */
    public static byte[] decrypt(byte[] key, byte[] data) throws Exception {
        Key desKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.DECRYPT_MODE, desKey);
        return cipher.doFinal(data);
    }
}
