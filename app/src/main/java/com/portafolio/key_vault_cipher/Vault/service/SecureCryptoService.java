package com.portafolio.key_vault_cipher.Vault.service;

import android.content.Context;
import android.content.Intent;
import android.util.Log;


import androidx.annotation.NonNull;
import androidx.core.app.JobIntentService;

import com.portafolio.key_vault_cipher.Vault.Core.HybridCryptoHelper;
import com.portafolio.key_vault_cipher.Vault.Core.SecureDatabaseHelper;

import java.util.concurrent.atomic.AtomicReference;

public class SecureCryptoService extends JobIntentService {

    private static final String TAG = "SecureCryptoService";
    public static final String ACTION_ENCRYPT = "encrypt";
    public static final String ACTION_DECRYPT = "decrypt";
    public static final String EXTRA_ACTION = "action";
    public static final String EXTRA_TEXT = "text";
    public static final String EXTRA_UUID = "uuid";
    public static final String EXTRA_IVPARAM = "ivparam";
    public static final String EXTRA_RESULT = "result";
    public static final String EXTRA_SUCCESS = "success";
    private static final int JOB_ID = 1000;

    @Override
    protected void onHandleWork(@NonNull Intent intent) {
        String action = intent.getStringExtra(EXTRA_ACTION);
        String text = intent.getStringExtra(EXTRA_TEXT);
        String uuid = intent.getStringExtra(EXTRA_UUID);
        String ivParam = intent.getStringExtra(EXTRA_IVPARAM);

        Log.d(TAG, "onHandleWork: " + action + " | text: " + text);

        AtomicReference<HybridCryptoHelper> crypto = new AtomicReference<>();
        SecureDatabaseHelper dbHelper;
        try {
            dbHelper = SecureDatabaseHelper.getInstance(this);
            new Thread(() -> {
                try {
                    crypto.set(HybridCryptoHelper.getInstance(this));
                    crypto.get().generateRSAKeyPair();
                    Log.d(TAG, "Clave RSA lista");
                } catch (Exception e) {
                    Log.e(TAG, "Error crypto", e);
                }
            }).start();

        } catch (Exception e) {
            sendResult(intent, false, "Fallo en inicialización: " + e.getMessage());
            return;
        }

        boolean success = false;
        String result = null;

        try {
            if (ACTION_ENCRYPT.equals(action)) {
                result = crypto.get().saveAfterEncrypt(this, text, uuid, ivParam);
                success = result != null;
            } else if (ACTION_DECRYPT.equals(action)) {
                result = dbHelper.decryptLastRecord(this);
                success = result != null;
            } else {
                sendResult(intent, false, "Acción no soportada");
                return;
            }
        } catch (Exception e) {
            sendResult(intent, false, "Error: " + e.getMessage());
            return;
        }

        sendResult(intent, success, result);
    }

    private void sendResult(Intent intent, boolean success, String result) {
        Intent reply = new Intent("com.tuapp.CRYPTO_RESULT");
        reply.putExtra(EXTRA_SUCCESS, success);
        reply.putExtra(EXTRA_RESULT, result);
        reply.putExtra(EXTRA_ACTION, intent.getStringExtra(EXTRA_ACTION));
        sendBroadcast(reply, "com.tuapp.permission.CRYPTO");
    }

    public static void enqueueWork(Context context, Intent work) {
        enqueueWork(context, SecureCryptoService.class, JOB_ID, work);
    }
}


