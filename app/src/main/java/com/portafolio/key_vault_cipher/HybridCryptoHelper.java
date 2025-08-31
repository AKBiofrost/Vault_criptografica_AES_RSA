package com.portafolio.key_vault_cipher;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class HybridCryptoHelper {

    private static final String TAG = "HybridCrypto";
    private static final String KEY_ALIAS = Build.DEVICE.toString();
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORM_RSA = "RSA/ECB/PKCS1Padding";
    private static final String TRANSFORM_AES = "AES/CBC/PKCS7Padding";

    private KeyStore keyStore;

    public HybridCryptoHelper() throws Exception {
        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
    }

    public void generateRSAKeyPair() throws KeyStoreException {
        if (keyStore.containsAlias(KEY_ALIAS)) return;

        try {
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,ANDROID_KEYSTORE);
            kpg.initialize(new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setKeySize(2048)
                    .build());
            kpg.generateKeyPair();
        } catch (Exception e) {
            Log.e(TAG, "Error generando RSA", e);
        }
    }

    public String encrypt(String plainText) {
        try {
            // AES
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
            kg.init(256);
            SecretKey aesKey = kg.generateKey();

            Cipher cipherAES = Cipher.getInstance(TRANSFORM_AES);
            cipherAES.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] iv = cipherAES.getIV();
            byte[] encryptedData = cipherAES.doFinal(plainText.getBytes());

            // RSA (cifrar clave AES)
            Cipher cipherRSA = Cipher.getInstance(TRANSFORM_RSA);
            PublicKey publicKey = ((java.security.KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null)).getCertificate().getPublicKey();
            cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedAESKey = cipherRSA.doFinal(aesKey.getEncoded());

            // Empaquetar: IV (16) + lenIV(4) + lenKey(4) + encryptedKey + data
            byte[] result = concat(
                    iv, toBytes(iv.length),
                    toBytes(encryptedAESKey.length),
                    encryptedAESKey,
                    encryptedData
            );

            return Base64.encodeToString(result, Base64.DEFAULT);
        } catch (Exception e) {
            Log.e(TAG, "Error cifrando", e);
            return null;
        }
    }

    public String decrypt(String encryptedBase64) {
        try {
            byte[] data = Base64.decode(encryptedBase64, Base64.DEFAULT);
            int offset = 0;

            byte[] iv = new byte[16];
            System.arraycopy(data, offset, iv, 0, 16);
            offset += 16;

            int ivLen = fromBytes(Arrays.copyOfRange(data, offset, offset + 4));
            offset += 4;

            int keyLen = fromBytes(Arrays.copyOfRange(data, offset, offset + 4));
            offset += 4;

            byte[] encryptedAESKey = new byte[keyLen];
            System.arraycopy(data, offset, encryptedAESKey, 0, keyLen);
            offset += keyLen;

            byte[] encryptedData = Arrays.copyOfRange(data, offset, data.length);

            // Descifrar clave AES con RSA
            Cipher cipherRSA = Cipher.getInstance(TRANSFORM_RSA);
            PrivateKey privateKey = ((java.security.KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null)).getPrivateKey();
            cipherRSA.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKey = cipherRSA.doFinal(encryptedAESKey);
            SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(decryptedKey, "AES");

            // Descifrar datos con AES
            Cipher cipherAES = Cipher.getInstance(TRANSFORM_AES);
            cipherAES.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] decrypted = cipherAES.doFinal(encryptedData);

            return new String(decrypted);
        } catch (Exception e) {
            Log.e(TAG, "Error descifrando", e);
            return null;
        }
    }

    public String getPublicKeyBase64() {
        try {
            PublicKey pub = ((java.security.KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null)).getCertificate().getPublicKey();
            return Base64.encodeToString(pub.getEncoded(), Base64.NO_WRAP);
        } catch (Exception e) {
            return null;
        }
    }

    // Auxiliares
    private byte[] toBytes(int value) {
        return new byte[]{
                (byte)(value >> 24),
                (byte)(value >> 16),
                (byte)(value >> 8),
                (byte)value
        };
    }

    private int fromBytes(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    private byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) len += a.length;
        byte[] result = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }
}