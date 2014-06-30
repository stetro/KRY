package de.stetro.mtin.kry.util;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class AESFileSecurityImpl implements AESFileSecurity {

    @Override
    public void encrypt(char[] password, String mode, InputStream file, String newFileName) throws Exception {
        byte[] salt = generateRandomBytes(64);
        int encryptMode = Cipher.ENCRYPT_MODE;
        action(password, mode, file, encryptMode, salt, newFileName);
    }

    @Override
    public void decrypt(char[] password, String mode, InputStream file, String newFileName) throws Exception {
        int decryptMode = Cipher.DECRYPT_MODE;
        byte[] salt = new byte[64];
        if (file.read(salt) >= 0) {
            action(password, mode, file, decryptMode, salt, newFileName);
        }
    }

    private void action(char[] password, String mode, InputStream file, int cryptMode, byte[] salt, String newFileName) throws Exception {
        byte[] pbkeyBytes = getKeyBy(salt, password);
        byte[] key = new byte[16];
        byte[] iv = new byte[16];

        splitBytes(pbkeyBytes, key, iv);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        CipherInputStream cipherInputStream = createCipherInputStream(mode, file, cryptMode, key, ivParameterSpec);
        FileOutputStream fileOutputStream = new FileOutputStream(new File(newFileName));
        if (cryptMode == Cipher.ENCRYPT_MODE) {
            fileOutputStream.write(salt);
        }

        byte[] buffer = new byte[1024];
        int len = cipherInputStream.read(buffer);
        while (len != -1) {
            fileOutputStream.write(buffer, 0, len);
            len = cipherInputStream.read(buffer);
        }
        closeStreams(file, cipherInputStream, fileOutputStream);
    }

    private void closeStreams(InputStream file, CipherInputStream cipherInputStream, FileOutputStream fileOutputStream) throws IOException {
        cipherInputStream.close();
        file.close();
        fileOutputStream.close();
    }

    private CipherInputStream createCipherInputStream(String mode, InputStream file, int decryptMode, byte[] key, IvParameterSpec ivParameterSpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(decryptMode, secretKeySpec, ivParameterSpec);
        return new CipherInputStream(file, cipher);
    }


    private static void splitBytes(byte[] pbkeyBytes, byte[] key, byte[] iv) {
        for (int i = 0; i < 32; i++) {
            if (i < 16) {
                key[i] = pbkeyBytes[i];
            } else {
                iv[i - 16] = pbkeyBytes[i];
            }
        }
    }

    private static byte[] getKeyBy(byte[] salt, char[] password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 1024, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return skf.generateSecret(spec).getEncoded();
    }

    private static byte[] generateRandomBytes(int i) {
        SecureRandom instance = new SecureRandom();
        byte[] key = new byte[i];
        instance.nextBytes(key);
        return key;
    }
}
