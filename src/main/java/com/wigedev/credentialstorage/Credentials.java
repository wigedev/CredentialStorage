package com.wigedev.credentialstorage;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Random;

/**
 * The Credentials class provides a mechanism for storing a username and "securely" storing a password in memory for
 * use during an application's runtime. This stores the password as an encrypted string to make it difficult for
 * diagnostic tools to extract the password from memory.
 */
public class Credentials
{
    private static final char[] SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 -._!@#$%^&*".toCharArray();
    private String username;
    private String encryptedPassword;
    private final char[] PASSWORD;
    private final byte[] SALT;

    Credentials()
    {
        PASSWORD = generateRandomishString(36);
        SALT = new String(generateRandomishString(8)).getBytes();
    }

    void setUsername(String username)
    {
        this.username = username;
    }

    String getUsername()
    {
        return username;
    }

    void setPassword(String password) throws GeneralSecurityException
    {
        setPassword(password.toCharArray());
        //noinspection UnusedAssignment
        password = null;
        System.gc();
    }

    void setPassword(char[] password) throws GeneralSecurityException
    {
        encryptedPassword = encrypt(password);
        //noinspection UnusedAssignment
        password = null;
        System.gc();
    }

    char[] getPassword() throws Base64DecodingException, GeneralSecurityException, IOException
    {
        return decrypt(encryptedPassword);
    }

    /**
     * The first step of encrypting the char[] password. This converts the password to bytes and then passes it on to
     * the second step to finish the encryption process. This also clears out the plain text password.
     *
     * @param data The plain text password
     *
     * @return The encrypted password
     *
     * @throws GeneralSecurityException if issues occur during encryption
     */
    String encrypt(char[] data) throws GeneralSecurityException
    {
        byte[] bytes = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            bytes[i] = (byte) data[i];
            data[i] = 0;
        }
        //noinspection UnusedAssignment
        data = null;
        System.gc();
        return encrypt(bytes);
    }

    /**
     * The second step of the encryption process. This encrypts each byte into a string and returns the encrypted data.
     *
     * @param data The bytes to encrypt
     *
     * @return The encrypted string
     *
     * @throws GeneralSecurityException if issues occur during encryption
     */
    private String encrypt(byte[] data) throws GeneralSecurityException
    {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey        key        = keyFactory.generateSecret(new PBEKeySpec(PASSWORD));
        Cipher           pbeCipher  = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(SALT, 20));
        String encrypted = Base64.encode(pbeCipher.doFinal(data));
        for (int i = 0; i < data.length; i++) {
            data[i] = 0;
        }
        //noinspection UnusedAssignment
        data = null;
        System.gc();
        return encrypted;
    }

    /**
     * Decrypt the encrypted string.
     */
    char[] decrypt(String data) throws GeneralSecurityException, IOException, Base64DecodingException
    {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(PASSWORD));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(SALT, 20));
        byte[] bytes = pbeCipher.doFinal(Base64.decode(data));
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            chars[i] = (char) bytes[i];
            bytes[i] = (byte) 0;
        }
        //noinspection UnusedAssignment
        bytes = null;
        System.gc();
        return chars;
    }

    private char[] generateRandomishString(int length)
    {
        StringBuilder salt = new StringBuilder();
        Random        rnd  = new Random();
        while(salt.length() < length) {
            int index = (int) (rnd.nextFloat() * SALTCHARS.length);
            salt.append(SALTCHARS[index]);
        }
        return salt.toString().toCharArray();
    }
}
