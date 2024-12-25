/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptchat;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Milos
 */
public class AsymmetricC {

    private static final String RSA = "RSA";
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricC() {
        
    }
    
    public void createNewKeys(){
        KeyPair kp = this.generateNewKeyPair();
        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();
    }

    private KeyPair generateNewKeyPair() {
        try {
            SecureRandom sr = new SecureRandom();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
            kpg.initialize(2048, sr);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    // Encryption
    public String encryptRSA(String plain, String publicKeyHex) {
        try {
            PublicKey pk = KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(this.hex2bytes(publicKeyHex)));
            Cipher c = Cipher.getInstance(RSA);
            c.init(Cipher.ENCRYPT_MODE, pk);
            byte[] bytes = c.doFinal(plain.getBytes());
            return Hex.toHexString(bytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public String sign(String plain){
        try {
            Signature privateSignature = Signature.getInstance("SHA1withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(plain.getBytes());
            byte[] signed = privateSignature.sign();
            return Hex.toHexString(signed);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
    
    public String encryptMessage(String plain, String publicKeyHex){ // Main encryption method used for communication between clients
        SymmetricC symmetric = new SymmetricC();
        symmetric.createNewKey(); // Create unique AES key for the message
        String cipherText = symmetric.encryptMessage(plain);
        String encodedKey = encryptRSA(symmetric.getKeyHex(), publicKeyHex); // Encrypt the AES key with the receivers public key using RSA
        String signed = this.sign(symmetric.getKeyHex()); // Sign the AES key with this users private key
        return encodedKey + "-" + signed + "-" + cipherText; // All three components are assembled into a string as seen
    }
    
    // Decryption
    public String decryptRSA(String cipher) {
        try {
            Cipher c = Cipher.getInstance(RSA);
            c.init(Cipher.DECRYPT_MODE, this.privateKey);
            byte[] decoded = c.doFinal(this.hex2bytes(cipher));
            return new String(decoded);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException  ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public boolean verify(String key, String signature, String publicKeyHex) {
        try {
            PublicKey pk = KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(this.hex2bytes(publicKeyHex)));
            Signature publicSignature =  Signature.getInstance("SHA1withRSA");
            publicSignature.initVerify(pk);
            publicSignature.update(key.getBytes());
            return publicSignature.verify(this.hex2bytes(signature));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(AsymmetricC.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }
    
    public String[] decryptMessage(String cipher, String publicKeyHex){ // Main decryption method used for communication between clients
        StringTokenizer st = new StringTokenizer(cipher, "-"); // Tokenize the received string which looks like: encryptedKey-signedKey-encryptedMessage
        String key = decryptRSA(st.nextToken()); // Decrypt the message unique AES key usng our private key with RSA
        String signature = st.nextToken();
        boolean verified = this.verify(key, signature, publicKeyHex); // Check if the signature is from the correct user
        SymmetricC symmetric = new SymmetricC(key); // Initalize the symmetric cryptography class with received AES key
        String message = symmetric.decryptMessage(st.nextToken()); // Decrypt the message
        String[] MessageVerify = new String[2]; // Create an array to store the message and the result of verification
        MessageVerify[0] = message;
        MessageVerify[1] = String.valueOf(verified);
        return MessageVerify;
    }

    public String getPublicKeyHex() {
        String keyHex = Hex.toHexString(this.publicKey.getEncoded());
        return keyHex;
    }

    public byte[] getPublicBytes() {
        return this.publicKey.getEncoded();
    }
    
    public String bytes2hex(byte[] bytes){
        return Hex.toHexString(bytes);
    }
    public byte[] hex2bytes(String hex){
        return Hex.decode(hex);
    }
}