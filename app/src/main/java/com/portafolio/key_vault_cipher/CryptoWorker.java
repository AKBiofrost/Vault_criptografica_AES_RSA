package com.portafolio.key_vault_cipher;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import androidx.work.Data;

import java.util.Map;

import android.content.Context;
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

    public CryptoWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        // Obtener entrada
        String action = getInputData().getString(ACTION);
        String text = getInputData().getString(TEXT);

        // Inicializar cripto
        HybridCryptoHelper crypto;
        try {
            crypto = new HybridCryptoHelper();
            crypto.generateRSAKeyPair();
        } catch (Exception e) {
            // ✅ Usa Data.Builder
            Data output = new Data.Builder()
                    .putString(SUCCESS, "false")
                    .putString(RESULT, "Fallo al inicializar: " + e.getMessage())
                    .build();
            return Result.failure(output);
        }

        String result = null;
        boolean success = false;

        try {
            if (ENCRYPT.equals(action)) {
                result = crypto.encrypt(text);
                success = (result != null);
            } else if (DECRYPT.equals(action)) {
                result = crypto.decrypt(text);
                success = (result != null);
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
