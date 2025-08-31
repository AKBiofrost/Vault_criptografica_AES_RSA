package com.portafolio.key_vault_cipher;

import net.sqlcipher.Cursor;
import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SQLiteOpenHelper;
import android.content.Context;
import android.content.ContentValues;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.content.ContentValues;
import android.content.Context;
import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SQLiteOpenHelper;
import android.util.Log;

public class SecureDatabaseHelper extends SQLiteOpenHelper {

    private static final String TAG = "SecureDatabaseHelper";
    private static final String DB_NAME = "vault.db";
    private static final int VERSION = 2; // Incrementada por nueva columna
    private static final String TABLE = "data";
    private static final String COL_ID = "id";
    private static final String COL_DATA = "encrypted_data";
    private static final String COL_KEY = "public_key_rsa";
    private static final String COL_AES_KEY = "encrypted_aes_key";

    private static SecureDatabaseHelper instance;
    private Context context;

    private SecureDatabaseHelper(Context context) {
        super(context, DB_NAME, null, VERSION);
        this.context = context.getApplicationContext();
        SQLiteDatabase.loadLibs(this.context);
    }

    // Singleton thread-safe
    public static synchronized SecureDatabaseHelper getInstance(Context context) {
        if (instance == null) {
            instance = new SecureDatabaseHelper(context);
        }
        return instance;
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE " + TABLE + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_DATA + " TEXT, " +
                COL_KEY + " TEXT, " +
                COL_AES_KEY + " TEXT);");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if (oldVersion < 2) {
            // Nueva columna para la clave AES cifrada
            db.execSQL("ALTER TABLE " + TABLE + " ADD COLUMN " + COL_AES_KEY + " TEXT;");
        }
        // En caso de futuras versiones, agregar más upgrades aquí
    }

    private String getPassword() {
        byte[] salt = SecurePreferences.getSalt(context);
        if (salt == null) {
            salt = CryptoUtils.generateSalt();
            SecurePreferences.saveSalt(context, salt);
        }
        return CryptoUtils.deriveKey("MiSemillaSuperSegura123", salt);
    }

    // Guardar datos cifrados
    public String saveEncryptedData(String data, String pubKey, String encryptedAESKey) {
        SQLiteDatabase db = getWritableDatabase(getPassword());
        ContentValues cv = new ContentValues();
        cv.put(COL_DATA, data);
        cv.put(COL_KEY, pubKey);
        cv.put(COL_AES_KEY, encryptedAESKey);
        long id = db.insert(TABLE, null, cv);
        db.close();
        Log.d(TAG, "Registro guardado ID: " + id);
        return String.valueOf(id);
    }

    // Leer último registro
    public EncryptedRecord getLastRecord() {
        SQLiteDatabase db = getReadableDatabase(getPassword());
        EncryptedRecord record = null;
        net.sqlcipher.Cursor cursor = db.query(TABLE,
                null,
                null, null, null, null,
                COL_ID + " DESC",
                "1");
        if (cursor != null && cursor.moveToFirst()) {
            String encryptedData = cursor.getString(cursor.getColumnIndexOrThrow(COL_DATA));
            String pubKey = cursor.getString(cursor.getColumnIndexOrThrow(COL_KEY));
            String encryptedAESKey = cursor.getString(cursor.getColumnIndexOrThrow(COL_AES_KEY));
            record = new EncryptedRecord(encryptedData, pubKey, encryptedAESKey);
            cursor.close();
        }
        return record;
    }

    // Clase auxiliar para devolver los datos
    public static class EncryptedRecord {
        public final String encryptedData;
        public final String publicKey;
        public final String encryptedAESKey;

        public EncryptedRecord(String encryptedData, String publicKey, String encryptedAESKey) {
            this.encryptedData = encryptedData;
            this.publicKey = publicKey;
            this.encryptedAESKey = encryptedAESKey;
        }
    }

    // Método de ejemplo para descifrar último registro usando HybridCryptoHelper
    public String decryptLastRecord(Context context) throws EncryptionException {
        EncryptedRecord record = getLastRecord();
        if (record == null) return null;

        HybridCryptoHelper crypto = HybridCryptoHelper.getInstance(context);
        // Aquí se pasa la clave AES cifrada al método de HybridCryptoHelper
        return crypto.rsaDecrypt(record.encryptedAESKey, record.encryptedData);
    }
}


