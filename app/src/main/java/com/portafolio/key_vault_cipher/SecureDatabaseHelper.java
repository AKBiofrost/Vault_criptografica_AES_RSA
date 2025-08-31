package com.portafolio.key_vault_cipher;

import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SQLiteOpenHelper;
import android.content.Context;
import android.content.ContentValues;

public class SecureDatabaseHelper extends SQLiteOpenHelper {

    private Context context;
    private static final String DB_NAME = "vault.db";
    private static final int VERSION = 1;
    private static final String TABLE = "data";
    private static final String COL_DATA = "encrypted_data";
    private static final String COL_KEY = "public_key_rsa";

    public SecureDatabaseHelper(Context context) {
        super(context, DB_NAME, null, VERSION);
        this.context = context.getApplicationContext();
        SQLiteDatabase.loadLibs(context);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE " + TABLE + " (id INTEGER PRIMARY KEY, " +
                COL_DATA + " TEXT, " + COL_KEY + " TEXT);");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int old, int newV) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE);
        onCreate(db);
    }

    private String getPassword() {
        byte[] salt = SecurePreferences.getSalt(context);
        if (salt == null) {
            salt = CryptoUtils.generateSalt();
            SecurePreferences.saveSalt(context, salt);
        }
        return CryptoUtils.deriveKey("MiSemillaSuperSegura123", salt);
    }

    public long saveEncryptedData(String data, String pubKey) {
        SQLiteDatabase db = getWritableDatabase(getPassword());
        ContentValues cv = new ContentValues();
        cv.put(COL_DATA, data);
        cv.put(COL_KEY, pubKey);
        long id = db.insert(TABLE, null, cv);
        db.close();
        return id;
    }

    public android.database.Cursor getLastRecord() {
        SQLiteDatabase db = getReadableDatabase(getPassword());
        return db.query(TABLE, null, null, null, null, null, "id DESC", "1");
    }
}
