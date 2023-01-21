package encryption;

import encryption.service.AESEncryption;
import encryption.service.DESEncryption;
import encryption.service.RSAEncryption;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

public class EncryptionExample {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // AES encryption example
        byte[] aesKey = AESEncryption.generateKey();
        byte[] data = "AES encryption example".getBytes();
        byte[] cipherText = AESEncryption.encrypt(aesKey, data);
        byte[] decryptedData = AESEncryption.decrypt(aesKey, cipherText);
        System.out.println("AES encryption example:");
        System.out.println("Original data: " + new String(data));
        System.out.println("Cipher text: " + Arrays.toString(cipherText));
        System.out.println("Decrypted data: " + new String(decryptedData));
        System.out.println();

        // DES encryption example
        byte[] desKey = DESEncryption.generateKey();
        data = "DES encryption example".getBytes();
        cipherText = DESEncryption.encrypt(desKey, data);
        decryptedData = DESEncryption.decrypt(desKey, cipherText);
        System.out.println("DES encryption example:");
        System.out.println("Original data: " + new String(data));
        System.out.println("Cipher text: " + Arrays.toString(cipherText));
        System.out.println("Decrypted data: " + new String(decryptedData));
        System.out.println();

        // RSA encryption example
        KeyPair rsaKeyPair = RSAEncryption.generateKeyPair();
        PublicKey publicKey = rsaKeyPair.getPublic();
        PrivateKey privateKey = rsaKeyPair.getPrivate();
        data = "RSA encryption example".getBytes();
        cipherText = RSAEncryption.encrypt(publicKey, data);
        decryptedData = RSAEncryption.decrypt(privateKey, cipherText);
        System.out.println("RSA encryption example:");
        System.out.println("Original data: " + new String(data));
        System.out.println("Cipher text: " + Arrays.toString(cipherText));
        System.out.println("Decrypted data: " + new String(decryptedData));
    }
}

