package encryption.service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * A class that provides methods for performing RSA encryption and decryption using the Bouncy Castle library
 * This class uses the "RSA/None/OAEPWithSHA1AndMGF1Padding" algorithm for encryption, and the "BC" provider for cryptographic operations.
 * This class uses the OAEP padding which is considered more secure than the standard RSA padding, but it will increase the size of the cipher text.
 */
public class RSAEncryption {
    /**
     * The encryption algorithm to be used
     */
    private static final String ALGORITHM = "RSA/None/OAEPWithSHA1AndMGF1Padding";
    /**
     * The key size in bits for the encryption algorithm
     */
    private static final int KEY_SIZE = 2048;

    /**
     * Generates a new RSA key pair
     *
     * @return the generated key pair
     * @throws Exception if there is an error generating the key pair
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Encrypts the given data using the given public key
     *
     * @param publicKey the public key to be used for encryption
     * @param data      the data to be encrypted
     * @return the encrypted data as a byte array
     * @throws Exception if there is an error encrypting the data
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts the given data using the given private key
     *
     * @param privateKey the private key to be used for decryption
     * @param data       the data to be decrypted
     * @return the decrypted data as a byte array
     * @throws Exception if there is an error decrypting the data
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * Converts the given encoded public key to a PublicKey instance
     * @param encodedKey the encoded public key as a byte array
     * @return the PublicKey instance
     * @throws Exception if there is an error converting the encoded key
     */
    public static PublicKey toPublicKey(byte[] encodedKey) throws Exception {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return keyFactory.generatePublic(publicKeySpec);
    }
}