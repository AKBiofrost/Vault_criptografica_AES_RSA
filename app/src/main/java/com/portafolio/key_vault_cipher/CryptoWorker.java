package com.portafolio.key_vault_cipher;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import androidx.work.Data;

import java.util.Map;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import androidx.work.Data;

import java.util.HashMap;
import java.util.Map;

public class CryptoWorker extends Worker {

    public static final String ACTION = "action";
    public static final String TEXT = "text";
    public static final String RESULT = "result";
    public static final String SUCCESS = "success";
    public static final String ENCRYPT = "encrypt";
    public static final String DECRYPT = "decrypt";
    public static final String UUID = "uuid";
    public static final String IVPARAM = "ivparam";
    private static Context context;

    public CryptoWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
        this.context = context;
    }

    @NonNull
    @Override
    public Result doWork() {
        // Obtener entrada
        String action = getInputData().getString(ACTION);
        String text = getInputData().getString(TEXT);
        String uuid = getInputData().getString(UUID);      // 👈 nuevo
        String ivParam = getInputData().getString(IVPARAM);  // 👈 nuevo
        // Inicializar cripto
        HybridCryptoHelper crypto = null;
        SecureDatabaseHelper dbHelper = null;
        try {
            crypto = HybridCryptoHelper.getInstance(context);
            dbHelper = SecureDatabaseHelper.getInstance(context);
        } catch (EncryptionException e) {
            throw new RuntimeException(e);
        }
        try {
            //crypto.resetKeyStore();
            crypto.generateRSAKeyPair();
        } catch (Exception e) {
            // ✅ Usa Data.Builder
            Data output = new Data.Builder()
                    .putString(SUCCESS, "false")
                    .putString(RESULT, "Fallo al inicializar: " + e.getMessage())
                    .build();
            return Result.failure(output);
        }

        String result = "6";
        boolean success = false;

        try {
            if (ENCRYPT.equals(action)) {

                //result = String.valueOf(crypto.saveAfterEncrypt(context, text, uuid, ivParam));
                success = (result != null);
            } else if (DECRYPT.equals(action)) {
                try {
                    result = dbHelper.decryptLastRecord(context);

                    success = (result != null);
                } catch (Exception e) {
                    Log.e("CriptoWorker", "ERROR: " + e.getMessage());
                }

            } else {
                Data output = new Data.Builder()
                        .putString(SUCCESS, "false")
                        .putString(RESULT, "Acción no soportada: " + action)
                        .build();
                return Result.failure(output);
            }
        } catch (Exception e) {
            Data output = new Data.Builder()
                    .putString(SUCCESS, "false")
                    .putString(RESULT, "Error: " + e.getMessage())
                    .build();
            return Result.failure(output);
        }

        // ✅ Construir resultado
        Data output = new Data.Builder()
                .putString(SUCCESS, String.valueOf(success))
                .putString(RESULT, result != null ? result : "null")
                .build();

        return success ? Result.success(output) : Result.failure(output);
    }
}
