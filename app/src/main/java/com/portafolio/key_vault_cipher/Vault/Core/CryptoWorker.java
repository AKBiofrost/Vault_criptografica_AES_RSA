package com.portafolio.key_vault_cipher.Vault.Core;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import androidx.work.Data;

import com.portafolio.key_vault_cipher.Vault.Core.Exception.EncryptionException;

public class CryptoWorker extends Worker {

    public static final String ACTION = "action";
    public static final String TEXT = "text";
    public static final String RESULT = "result";
    public static final String SUCCESS = "success";
    public static final String ENCRYPT = "encrypt";
    public static final String DECRYPT = "decrypt";
    public static final String UUID = "uuid";
    public static final String IVPARAM = "ivparam";

    private final Context context;

    public CryptoWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
        this.context = context;
    }

    @NonNull
    @Override
    public Result doWork() {
        String action = getInputData().getString(ACTION);
        String text = getInputData().getString(TEXT);
        String uuid = getInputData().getString(UUID);
        String ivParam = getInputData().getString(IVPARAM);

        HybridCryptoHelper crypto;
        SecureDatabaseHelper dbHelper;

        try {
            crypto = HybridCryptoHelper.getInstance(context);
            dbHelper = SecureDatabaseHelper.getInstance(context);
            crypto.generateRSAKeyPair();
        } catch (EncryptionException e) {
            return failure("Fallo al inicializar HybridCryptoHelper: " + e.getMessage());
        }

        try {
            String result;
            boolean success;

            if (ENCRYPT.equals(action)) {
                result = crypto.saveAfterEncrypt(context, text, uuid, ivParam);
                success = result != null;

            } else if (DECRYPT.equals(action)) {
                result = dbHelper.decryptLastRecord(context);
                success = result != null;

            } else {
                return failure("Acción no soportada: " + action);
            }

            return buildResult(success, result);

        } catch (Exception e) {
            return failure("Error durante operación: " + e.getMessage());
        }
    }

    private Result failure(String message) {
        Data output = new Data.Builder()
                .putString(SUCCESS, "false")
                .putString(RESULT, message)
                .build();
        return Result.failure(output);
    }

    private Result buildResult(boolean success, String result) {
        Data output = new Data.Builder()
                .putString(SUCCESS, String.valueOf(success))
                .putString(RESULT, result != null ? result : "null")
                .build();
        return success ? Result.success(output) : Result.failure(output);
    }
}

