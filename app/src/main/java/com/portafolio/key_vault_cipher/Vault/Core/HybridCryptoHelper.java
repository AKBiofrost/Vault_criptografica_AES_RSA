package com.portafolio.key_vault_cipher.Vault.Core;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.portafolio.key_vault_cipher.Vault.Core.Exception.EncryptionException;
import com.portafolio.key_vault_cipher.Vault.Core.Model.EncryptedResult;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.UUID;

public class HybridCryptoHelper {

    private static final String TAG = "HybridCrypto";
    private static final String KEY_ALIAS = "HybridCryptoHelper";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORM_RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String TRANSFORM_AES = "AES/GCM/NoPadding";
    private static final OAEPParameterSpec OAEP_SHA256_MGF1_SHA1 =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

    private KeyStore keyStore;
    private static HybridCryptoHelper instance;
    static SecureDatabaseHelper dbHelper;

    public HybridCryptoHelper() throws EncryptionException {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
        } catch (Exception e) {
            throw EncryptionException.keyManagementError("Error inicializando KeyStore", e);
        }
    }

    public static synchronized HybridCryptoHelper getInstance(Context context) throws EncryptionException {
        if (instance == null) {
            dbHelper = SecureDatabaseHelper.getInstance(context);
            instance = new HybridCryptoHelper();
        }
        return instance;
    }

    public void generateRSAKeyPair() throws EncryptionException {
        try {
            if (keyStore.containsAlias(KEY_ALIAS)) return;

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .build();

            kpg.initialize(spec);
            kpg.generateKeyPair();
        } catch (Exception e) {
            throw EncryptionException.keyManagementError("Error generando RSA key pair", e);
        }
    }

    public EncryptedResult encrypt(String plainText, String uuidStr, String ivParam) throws EncryptionException {
        try {
            if (plainText == null || plainText.isEmpty()) throw new IllegalArgumentException("Texto plano no puede ser nulo");
            if (uuidStr == null || uuidStr.trim().isEmpty()) uuidStr = UUID.randomUUID().toString();

            byte[] iv = generateIV(uuidStr, ivParam);

            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
            kg.init(256);
            SecretKey aesKey = kg.generateKey();

            Cipher cipherAES = Cipher.getInstance(TRANSFORM_AES);
            cipherAES.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            byte[] encryptedData = cipherAES.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] authTag = Arrays.copyOfRange(encryptedData, encryptedData.length - 16, encryptedData.length);
            byte[] encryptedDataWithoutTag = Arrays.copyOfRange(encryptedData, 0, encryptedData.length - 16);

            PublicKey publicKey = getPublicKey();
            Cipher cipherRSA = Cipher.getInstance(TRANSFORM_RSA);
            cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SHA256_MGF1_SHA1);
            byte[] encryptedAESKey = cipherRSA.doFinal(aesKey.getEncoded());

            byte[] packagedData = packageEncryptedData(uuidStr, iv, authTag, encryptedDataWithoutTag);

            return new EncryptedResult(
                    Base64.encodeToString(packagedData, Base64.NO_WRAP),
                    Base64.encodeToString(encryptedAESKey, Base64.NO_WRAP)
            );

        } catch (Exception e) {
            throw EncryptionException.encryptionError("Error en cifrado", e);
        }
    }

    private byte[] packageEncryptedData(String uuidStr, byte[] iv, byte[] authTag, byte[] encryptedDataWithoutTag) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(output);

            dos.writeUTF(uuidStr);
            dos.write(iv);
            dos.write(authTag);
            dos.writeInt(encryptedDataWithoutTag.length);
            dos.write(encryptedDataWithoutTag);

            return output.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Error empaquetando datos", e);
        }
    }

    public String rsaDecrypt(String encryptedAESKeyBase64, String encryptedDataBase64) throws EncryptionException {
        try {
            byte[] encryptedAESKey = Base64.decode(encryptedAESKeyBase64, Base64.NO_WRAP);
            byte[] encryptedData = Base64.decode(encryptedDataBase64, Base64.NO_WRAP);

            PrivateKey privateKey = getPrivateKey();
            Cipher cipherRSA = Cipher.getInstance(TRANSFORM_RSA);
            cipherRSA.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SHA256_MGF1_SHA1);
            byte[] aesKeyBytes = cipherRSA.doFinal(encryptedAESKey);

            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encryptedData));
            String uuidStr = dis.readUTF();
            byte[] iv = new byte[12]; dis.readFully(iv);
            byte[] authTag = new byte[16]; dis.readFully(authTag);

            int dataLength = dis.readInt();
            validateSize(dataLength, 0, 10 * 1024 * 1024);
            byte[] encryptedDataWithoutTag = new byte[dataLength];
            dis.readFully(encryptedDataWithoutTag);

            byte[] fullEncryptedData = concat(encryptedDataWithoutTag, authTag);

            Cipher cipherAES = Cipher.getInstance(TRANSFORM_AES);
            cipherAES.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            byte[] decryptedData = cipherAES.doFinal(fullEncryptedData);

            return new String(decryptedData, StandardCharsets.UTF_8);

        } catch (Exception e) {
            Log.e(TAG, "rsaDecrypt: " + e.getMessage());
            throw EncryptionException.decryptionError("Error en rsaDecrypt()", e);
        }
    }

    // --- KeyStore Helpers ---
    private PublicKey getPublicKey() throws EncryptionException {
        try {
            if (!keyStore.containsAlias(KEY_ALIAS)) generateRSAKeyPair();
            KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
            return ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
        } catch (Exception e) {
            throw EncryptionException.keyManagementError("Error obteniendo clave pública", e);
        }
    }

    private PrivateKey getPrivateKey() throws EncryptionException {
        try {
            if (!keyStore.containsAlias(KEY_ALIAS)) generateRSAKeyPair();
            KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
            return ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        } catch (Exception e) {
            throw EncryptionException.keyManagementError("Error obteniendo clave privada", e);
        }
    }

    private byte[] concat(byte[]... arrays) {
        int total = 0; for (byte[] a : arrays) total += a.length;
        byte[] r = new byte[total]; int pos = 0;
        for (byte[] a : arrays) { System.arraycopy(a, 0, r, pos, a.length); pos += a.length; }
        return r;
    }

    private void validateSize(int size, int min, int max) throws EncryptionException {
        if (size < min || size > max) throw new EncryptionException("Tamaño inválido");
    }

    private byte[] generateIV(String uuidStr, String parameter) throws NoSuchAlgorithmException {
        String seed = uuidStr + (parameter != null ? parameter : "");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(seed.getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(hash, 12);
    }

    public String saveAfterEncrypt(Context ctx, String plainText, String uuid, String ivParam) throws EncryptionException {
        try {
            HybridCryptoHelper crypto = HybridCryptoHelper.getInstance(ctx);
            crypto.generateRSAKeyPair();

            EncryptedResult result = crypto.encrypt(plainText, uuid, ivParam);

            PublicKey pubKey = crypto.getPublicKey();
            String publicKeyPem = Base64.encodeToString(pubKey.getEncoded(), Base64.NO_WRAP);

            // Guardar en DB cifrada con clave AES cifrada
            return String.valueOf(SecureDatabaseHelper.getInstance(ctx)
                    .saveEncryptedData(result.packagedDataBase64, publicKeyPem, result.encryptedAESKeyBase64));

        } catch (Exception e) {
            throw EncryptionException.encryptionError("Fallo en saveAfterEncrypt()", e);
        }
    }


}
