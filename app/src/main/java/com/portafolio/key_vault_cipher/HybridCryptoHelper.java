package com.portafolio.key_vault_cipher;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
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

import java.security.UnrecoverableEntryException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.Executors;

public class HybridCryptoHelper {

    private static final String TAG = "HybridCrypto";
    private static final String KEY_ALIAS = "HybridCryptoHelper";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORM_RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String TRANSFORM_AES = "AES/GCM/NoPadding";
    // Parámetros OAEP compatibles en muchos dispositivos:
    private static final OAEPParameterSpec OAEP_SHA256_MGF1_SHA1 =
            new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    private KeyStore keyStore;

    // 🔒 instancia única
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
    // 🔒 getter thread-safe
    public static synchronized HybridCryptoHelper getInstance(Context context) throws EncryptionException {
        if (instance == null) {
            dbHelper  = SecureDatabaseHelper.getInstance(context);
            instance = new HybridCryptoHelper();
        }
        return instance;
    }
    public void generateRSAKeyPair() throws EncryptionException, KeyStoreException {
        if (keyStore.containsAlias(KEY_ALIAS)) return;

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setDigests(
                            KeyProperties.DIGEST_SHA1,      // ← añade SHA-1
                            KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA512
                    )
                    .setKeySize(2048)
                    .setUserAuthenticationRequired(false); // opcional, evita errores de auth


            kpg.initialize(builder.build());
            kpg.generateKeyPair();

        } catch (Exception e) {
            throw EncryptionException.keyManagementError("Error generando par de claves RSA", e);
        }
    }

    public String encrypt(String plainText, String uuidStr, String ivParameter) throws EncryptionException {
        try {
            // Validaciones
            if (plainText == null || plainText.isEmpty()) {
                throw new IllegalArgumentException("Texto plano no puede ser nulo o vacío");
            }
            if (uuidStr == null || uuidStr.trim().isEmpty()) {
                uuidStr = UUID.randomUUID().toString();
            }

            // 1. Generar IV usando UUID y parámetro
            byte[] iv = generateIV(uuidStr, ivParameter);

            // 2. Generar clave AES
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
            kg.init(256);
            SecretKey aesKey = kg.generateKey();

            // 3. Cifrar datos con AES-GCM
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            Cipher cipherAES = Cipher.getInstance(TRANSFORM_AES);
            cipherAES.init(Cipher.ENCRYPT_MODE, aesKey, spec);

            byte[] encryptedData = cipherAES.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // Separar tag de autenticación de los datos cifrados
            byte[] authTag = Arrays.copyOfRange(encryptedData, encryptedData.length - 16, encryptedData.length);
            byte[] encryptedDataWithoutTag = Arrays.copyOfRange(encryptedData, 0, encryptedData.length - 16);

            // 4. Cifrar clave AES con RSA
            PublicKey publicKey = getPublicKey();
            Cipher cipherRSA = Cipher.getInstance(TRANSFORM_RSA);
            cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SHA256_MGF1_SHA1);
            byte[] encryptedAESKey = cipherRSA.doFinal(aesKey.getEncoded());

            // 5. Empaquetar todos los componentes
            byte[] packagedData = packageEncryptedData(uuidStr, iv, authTag, encryptedAESKey, encryptedDataWithoutTag);

            // 6. Codificar en Base64 para transporte
            return Base64.encodeToString(packagedData, Base64.NO_WRAP);

        } catch (Exception e) {
            throw EncryptionException.encryptionError("Error en cifrado", e);
        }
    }

    public String saveAfterEncrypt(Context ctx, String plainText, String uuid, String ivParam) throws EncryptionException {
        try {
            // 1. Obtener instancia de cripto
            HybridCryptoHelper crypto = HybridCryptoHelper.getInstance(ctx);

            // 2. Asegurar par de llaves
            crypto.generateRSAKeyPair();

            // 3. Cifrar el texto plano
            String encryptedData = crypto.encrypt(plainText, uuid, ivParam);

            // 4. Exportar clave pública en Base64/PEM
            PublicKey pubKey = crypto.getPublicKey();
            String publicKeyPem = Base64.encodeToString(pubKey.getEncoded(), Base64.NO_WRAP);

            // 5. Guardar en DB cifrada
            return dbHelper.saveEncryptedData(encryptedData, publicKeyPem);

        } catch (Exception e) {
            throw EncryptionException.encryptionError("Fallo en saveAfterEncrypt()", e);
        }
    }


    private byte[] packageEncryptedData(String uuidStr, byte[] iv, byte[] authTag,
                                        byte[] encryptedAESKey, byte[] encryptedDataWithoutTag) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(output);

            // 1. Escribir UUID con writeUTF() (ESTO ES CLAVE)
            dos.writeUTF(uuidStr);

            // 2. Componentes fijos
            dos.write(iv);          // 12 bytes
            dos.write(authTag);     // 16 bytes

            // 3. Clave AES cifrada
            dos.writeInt(encryptedAESKey.length);
            dos.write(encryptedAESKey);

            // 4. Datos cifrados (sin tag)
            dos.writeInt(encryptedDataWithoutTag.length);
            dos.write(encryptedDataWithoutTag);

            return output.toByteArray();

        } catch (IOException e) {
            throw new RuntimeException("Error empaquetando datos", e);
        }
    }

    public String decrypt(String encryptedBase64) throws EncryptionException {
        Log.d(TAG, "decrypt() called with: encryptedBase64 = [" + encryptedBase64 + "]");
        try {
            byte[] encryptedData = Base64.decode(encryptedBase64, Base64.NO_WRAP);
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encryptedData));

            // 1. Leer UUID con readUTF() (COMPATIBLE con writeUTF)
            String uuidStr = dis.readUTF();
            Log.e(TAG, "UUID-decrypt:" + uuidStr);
            // Validar UUID
            if (uuidStr == null || uuidStr.length() < 36 || uuidStr.length() > 100) {
                throw EncryptionException.formatError("UUID inválido: " + uuidStr, null);
            }

            // 2. Leer componentes fijos
            byte[] iv = new byte[12];
            dis.readFully(iv);

            byte[] authTag = new byte[16];
            dis.readFully(authTag);

            // 3. Leer longitud de clave AES
            int keyLength = dis.readInt();
            validateSize(keyLength, 1, 2048); // 2048 bytes máximo para clave RSA

            byte[] encryptedAESKey = new byte[keyLength];
            dis.readFully(encryptedAESKey);

            // 4. Leer longitud de datos
            int dataLength = dis.readInt();
            validateSize(dataLength, 0, 10 * 1024 * 1024); // 10MB máximo

            byte[] encryptedDataWithoutTag = new byte[dataLength];
            dis.readFully(encryptedDataWithoutTag);

            // 5. Verificar fin de stream
            if (dis.available() > 0) {
                Log.w(TAG, "Quedan " + dis.available() + " bytes sin leer");
            }

            // Resto del proceso de descifrado...
            byte[] fullEncryptedData = concat(encryptedDataWithoutTag, authTag);
            PrivateKey privateKey = null;
            try {
                privateKey = getPrivateKey();
            } catch (EncryptionException e) {
                Log.e(TAG, "EXCEPCION PRIVATE KEY: " + e.getMessage());
            }


            Cipher cipherRSA = Cipher.getInstance(TRANSFORM_RSA);
            cipherRSA.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SHA256_MGF1_SHA1);
            byte[] aesKeyBytes = cipherRSA.doFinal(encryptedAESKey);

            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            Cipher cipherAES = Cipher.getInstance(TRANSFORM_AES);
            cipherAES.init(Cipher.DECRYPT_MODE, aesKey, spec);

            byte[] decryptedData = cipherAES.doFinal(fullEncryptedData);

            return new String(decryptedData, StandardCharsets.UTF_8);

        } catch (Exception e) {
            Log.e(TAG, "Excepcion: " + e.getMessage());
            Log.e(TAG, "Excepcion: " + e.getCause());
            throw EncryptionException.decryptionError("Error en descifrado", e);
        }
    }

    /**
     * Lee completamente un array de bytes desde el stream
     */
    private void validateSize(int size, int min, int max) throws EncryptionException {
        if (size < min) {
            throw EncryptionException.formatError(
                    "Tamaño demasiado pequeño: " + size + " (mínimo: " + min + ")", null);
        }
        if (size > max) {
            throw EncryptionException.formatError(
                    "Tamaño demasiado grande: " + size + " (máximo: " + max + ")", null);
        }
    }


    public String getUUIDFromEncryptedData(String encryptedBase64) throws EncryptionException {
        try {
            byte[] encryptedData = Base64.decode(encryptedBase64, Base64.NO_WRAP);
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encryptedData));

            // ✅ Leer UUID correctamente
            String uuidStr = dis.readUTF();

            return uuidStr;
        } catch (Exception e) {
            throw new EncryptionException("Error extrayendo UUID", e);
        }
    }



    public boolean verifyAuthentication(String encryptedBase64) {
        try {
            // Intentar descifrar - si falla la autenticación, lanzará BadPaddingException
            decrypt(encryptedBase64);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void readFully(InputStream input, byte[] buffer) throws IOException {
        int bytesRead = 0;
        while (bytesRead < buffer.length) {
            int count = input.read(buffer, bytesRead, buffer.length - bytesRead);
            if (count == -1) {
                throw new IOException("Fin de stream inesperado");
            }
            bytesRead += count;
        }
    }

    /**
     * Convierte bytes a entero (big-endian)
     */
    private int bytesToInt(byte[] bytes) {
        if (bytes.length != 4) {
            throw new IllegalArgumentException("El array debe tener exactamente 4 bytes");
        }
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }


    /**
     * Convierte un entero a array de bytes (big-endian)
     *
     * @param value El entero a convertir
     * @return Array de 4 bytes
     */
    private byte[] intToBytes(int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value
        };
    }


    private byte[] generateIV(String uuidStr, String parameter) throws NoSuchAlgorithmException {
        try {
            // Validar que el UUID no sea nulo o vacío
            if (uuidStr == null || uuidStr.trim().isEmpty()) {
                throw new IllegalArgumentException("UUID no puede ser nulo o vacío");
            }

            // Concatenar UUID + parámetro (el parámetro puede ser nulo)
            String seed = uuidStr + (parameter != null ? parameter : "");

            // Obtener hash SHA-256 de la semilla
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(seed.getBytes(StandardCharsets.UTF_8));

            // Tomar los primeros 12 bytes del hash como IV
            byte[] iv = new byte[12];
            System.arraycopy(hash, 0, iv, 0, 12);

            return iv;

        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("Algoritmo SHA-256 no disponible", e);
        }
    }


  /*
   private byte[] generateIV() {
        byte[] iv = new byte[12]; // tamaño recomendado para AES-GCM
        new SecureRandom().nextBytes(iv);
        return iv;
    }
*/

    public void DesencryptAsync(
            String encryptedBase64,
            EncryptCallback callback
    ) {
        Executors.newSingleThreadExecutor().submit(() -> {
            try {
                String result = decrypt(encryptedBase64);
                callback.onSuccess(result);
            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }


  public void encryptAsync(
          String plainText,
          String uuidStr,
          String ivParameter,
          EncryptCallback callback
  ) {
      Executors.newSingleThreadExecutor().submit(() -> {
          try {
              String result = encrypt(plainText, uuidStr, ivParameter);
              callback.onSuccess(result);
          } catch (Exception e) {
              callback.onError(e);
          }
      });
  }

    private PublicKey getPublicKey() throws EncryptionException {
        try {
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                // Crear la clave si no existe
                generateRSAKeyPair();
            }

            KeyStore.Entry keyEntry = keyStore.getEntry(KEY_ALIAS, null);

            if (keyEntry instanceof KeyStore.PrivateKeyEntry) {
                return ((KeyStore.PrivateKeyEntry) keyEntry).getCertificate().getPublicKey();
            } else {
                throw EncryptionException.keyManagementError(
                        "El alias no contiene un par de claves RSA", null);
            }

        } catch (Exception e) {
            throw EncryptionException.keyManagementError("Error obteniendo clave pública", e);
        }
    }

    private PrivateKey getPrivateKey() throws EncryptionException {
        try {
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                generateRSAKeyPair();
            }

            KeyStore.Entry keyEntry = keyStore.getEntry(KEY_ALIAS, null);

            if (keyEntry instanceof KeyStore.PrivateKeyEntry) {
                return ((KeyStore.PrivateKeyEntry) keyEntry).getPrivateKey();
            } else {
                throw EncryptionException.keyManagementError("El alias no contiene una clave privada RSA", null);
            }

        } catch (UnrecoverableEntryException e) {
            // 🚨 La clave no se puede recuperar → regenerar
            try {
                keyStore.deleteEntry(KEY_ALIAS);
                generateRSAKeyPair();
                KeyStore.Entry keyEntry = keyStore.getEntry(KEY_ALIAS, null);
                return ((KeyStore.PrivateKeyEntry) keyEntry).getPrivateKey();
            } catch (Exception inner) {
                throw EncryptionException.keyManagementError("Error regenerando claves tras UnrecoverableEntryException", inner);
            }
        } catch (Exception e) {
            throw EncryptionException.keyManagementError("Error accediendo al KeyStore", e);
        }
    }


    public void resetKeyStore() throws EncryptionException {
        try {
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS);
                Log.i(TAG, "Clave eliminada: " + KEY_ALIAS);
            }

            // Regenerar clave
            generateRSAKeyPair();

        } catch (Exception e) {
            throw EncryptionException.keyManagementError("Error reseteando KeyStore", e);
        }
    }

    public boolean isKeyStoreAvailable() {
        try {
            KeyStore testKeyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            testKeyStore.load(null);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "KeyStore no disponible: " + e.getMessage());
            return false;
        }
    }

    public String getPublicKeyBase64() {
        try {
            PublicKey pub = ((KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null)).getCertificate().getPublicKey();
            return Base64.encodeToString(pub.getEncoded(), Base64.NO_WRAP);
        } catch (Exception e) {
            return null;
        }
    }

    // Auxiliares
    private byte[] toBytes(int value) {
        return new byte[]{
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
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

    public void verifyKeyCompatibility() {
        try {
            HybridCryptoHelper crypto = new HybridCryptoHelper();

            // Verificar que podemos obtener ambas claves
            PublicKey publicKey = crypto.getPublicKey();
            PrivateKey privateKey = crypto.getPrivateKey();

            Log.d(TAG, "Clave pública algoritmo: " + publicKey.getAlgorithm());
            Log.d(TAG, "Clave privada algoritmo: " + privateKey.getAlgorithm());

            // Prueba de cifrado/descifrado con RSA
            String testData = "Test RSA OAEP";
            Cipher cipher = Cipher.getInstance(TRANSFORM_RSA);

            // Cifrar con pública
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(testData.getBytes());

            // Descifrar con privada
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = cipher.doFinal(encrypted);

            String result = new String(decrypted);
            if (testData.equals(result)) {
                Log.d(TAG, "✅ RSA OAEP funciona correctamente");
            } else {
                Log.d(TAG, "❌ RSA OAEP falló");
            }

        } catch (Exception e) {
            Log.e(TAG, "Error en verificación: " + e.getMessage());
        }
    }

    public void checkAlgorithmSupport() {
        try {
            // Verificar soporte de OAEP
            Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            Log.d(TAG, "OAEPWithSHA-256AndMGF1Padding: ✅ Soportado");
        } catch (Exception e) {
            Log.d(TAG, "OAEPWithSHA-256AndMGF1Padding: ❌ No soportado");
        }

        try {
            // Verificar soporte de PKCS1
            Cipher.getInstance("RSA/ECB/PKCS1Padding");
            Log.d(TAG, "PKCS1Padding: ✅ Soportado");
        } catch (Exception e) {
            Log.d(TAG, "PKCS1Padding: ❌ No soportado");
        }
    }
    public interface EncryptCallback {
        void onSuccess(String encryptedBase64);
        void onError(Exception e);
    }


}