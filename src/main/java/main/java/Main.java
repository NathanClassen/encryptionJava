package main.java;

import org.json.JSONObject;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;


public class Main {

    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    public static final int GCM_TAG_LENGTH = 16; // in bytes

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException, InvalidAlgorithmParameterException {

        byte[] url = performEncryption();
//        performDecryption("QfVjmYHZESKiFa_xJvThr6jGB5hh4iIQtZ_f_rxEgpC8aUAh38M8U5eXwGmYOQG3I5mn-Cw2tES9m4dam8qQPckeMLaMBanfYSzMpTAZQJDGKXqlOOYYqtGl0vGxZXDHaDK4ZcQmM29S0dgvxOeTsKgFuZ39BK5do_cbvqR-rEMVDgLNNPAHhRMAdf9JF7Fa".getBytes());
//        generateKey(256);
    }

    public static byte[] performEncryption() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {

        byte[] cipherKey = "bYtkqv1TdvHQXtKVlahHSXAQJHUaUoA4bAgaotIjRKk=".getBytes(); // turn AWS.getSecret() into bytes

        byte[] decodedKeyBytes = Base64.getDecoder().decode(cipherKey);
        String decodedString = new String(decodedKeyBytes);
        System.out.println("DECODED: " + decodedString);

        Key key = new SecretKeySpec(decodedKeyBytes, "AES"); // create AES key with those bytes

        SecureRandom random = SecureRandom.getInstanceStrong();



        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);







        Cipher encryptionCipher = Cipher.getInstance("AES"); // create an AES cipher

        encryptionCipher.init(Cipher.ENCRYPT_MODE, key); // initialize cipher to encryption mode, using created key

        String baseUrl = "https://watermark-go.stg1.ti.pythagoras.io/images?details=";

        JSONObject details = new JSONObject();
        details.put("SignedURL","ewfwefewfewfewfewfewf.s3.us-east-2.amazonaws.com/2.png");
        details.put("SubscriberName", "Vincent");
        details.put("SubscriberEmail", "haha@funn.com");

        String urlToWaterMarker = "google.com";

        byte[] encryptedURL = cipher.doFinal(details.toString().getBytes());
        byte[] encodedDetails = Base64.getUrlEncoder().encode(encryptedURL);
        String encryptedDetailsString = new String(encodedDetails, StandardCharsets.UTF_8);

        String watermarkUrl = baseUrl + encryptedDetailsString;


        System.out.println("Encrypted URL: " + watermarkUrl);

        return encryptedURL;
    }

    public static void performDecryption(byte[] toDecrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] cipherKey = "bYtkqv1TdvHQXtKVlahHSXAQJHUaUoA4bAgaotIjRKk".getBytes(); // turn AWS.getSecret() into bytes

        byte[] decodedKeyBytes = Base64.getDecoder().decode(cipherKey);
        String decodedString = new String(decodedKeyBytes);
        System.out.println("DECODED: " + decodedString);

        Key key = new SecretKeySpec(decodedKeyBytes, "AES"); // create AES key with those bytes

        Cipher decryptionCipher = Cipher.getInstance("AES/GCM"); // create an AES cipher

        decryptionCipher.init(Cipher.DECRYPT_MODE, key); // initialize cipher to encryption mode, using created key


        byte[] decryptedURL = decryptionCipher.doFinal(toDecrypt);
        String decryptedURLString = new String(decryptedURL, StandardCharsets.UTF_8);


        System.out.println("Decrypted URL: " + decryptedURLString);


    }

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();

        byte[] stuff = key.getEncoded();

        String stuffString = new String(stuff, StandardCharsets.UTF_8);
        System.out.println("STUFF: " + stuffString);

        System.out.println("GET ENCODED: " + stuff);

        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());

        System.out.println("ENCODED KEY: " + encodedKey);

        byte[] decodedBytes = Base64.getDecoder().decode(encodedKey);
        String decodedString = new String(decodedBytes);
        System.out.println("DECODED: " + decodedString);

        return key;
    }



}



