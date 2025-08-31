package com.portafolio.key_vault_cipher;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;


import androidx.core.app.JobIntentService;

import java.util.Arrays;

public class SecureCryptoService extends JobIntentService {

    private static final String TAG = "SecureCryptoService";
    public static final String ACTION_ENCRYPT = "encrypt";
    public static final String ACTION_DECRYPT = "decrypt";
    public static final String EXTRA_ACTION = "action";
    public static final String EXTRA_TEXT = "text";
    public static final String EXTRA_RESULT = "result";
    public static final String EXTRA_SUCCESS = "success";

    // Debe ser un ID único para JobIntentService
    private static final int JOB_ID = 1000;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "🟢 Servicio creado en proceso: " + android.os.Process.myPid());
    }

    // Llamar desde la Activity
    public static void enqueueWork(MainActivity context, Intent work) {
        enqueueWork(context, SecureCryptoService.class, JOB_ID, work);
    }

    @Override
    protected void onHandleWork(Intent intent) {
        Log.d(TAG, "✅ onHandleWork llamado. Acción: " + intent.getStringExtra(EXTRA_ACTION));

        String action = intent.getStringExtra(EXTRA_ACTION);
        Log.d(TAG, "✅ Acción recibida: " + action);
        if (action == null) {
            Log.e(TAG, "❌ Acción nula en intent");
            sendResult(intent, false, "Acción no especificada");
            return;
        }

        String text = intent.getStringExtra(EXTRA_TEXT);
        if (text == null) {
            Log.w(TAG, "⚠️ Texto nulo, usando vacío");
            text = "";
        } else {
            Log.d(TAG, "📄 Texto recibido: " + text.substring(0, Math.min(20, text.length())) + "...");
        }

        HybridCryptoHelper crypto = null;
        try {
            crypto = new HybridCryptoHelper();
            Log.d(TAG, "🔑 HybridCryptoHelper creado");
            crypto.generateRSAKeyPair();
            Log.d(TAG, "✅ Clave RSA lista");
        } catch (Exception e) {
            Log.e(TAG, "❌ Error inicializando cripto", e);
            sendResult(intent, false, "Fallo en cripto: " + e.getMessage());
            return;
        }

        String result = null;
        boolean success = false;
/*
        try {
            if (ACTION_ENCRYPT.equals(action)) {
                Log.d(TAG, "🔐 Iniciando cifrado...");
                result = crypto.encrypt(text, "0123456789012345678901234567890123456789", "VTID");
                success = result != null;
                if (success) {
                    Log.d(TAG, "✅ Cifrado exitoso, largo: " + result.length());
                } else {
                    Log.e(TAG, "❌ Cifrado devolvió null");
                }
            } else if (ACTION_DECRYPT.equals(action)) {
                Log.d(TAG, "🔓 Iniciando descifrado...");
                result = crypto.decrypt(text);
                success = result != null;
                if (success) {
                    Log.d(TAG, "✅ Descifrado exitoso: " + result);
                } else {
                    Log.e(TAG, "❌ Descifrado devolvió null");
                }
            } else {
                Log.e(TAG, "❌ Acción no soportada: " + action);
                sendResult(intent, false, "Acción inválida");
                return;
            }
        } catch (Exception e) {
            Log.e(TAG, "❌ Excepción en operación", e);
            sendResult(intent, false, "Error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            return;
        } finally {
            // Mejor esfuerzo para limpiar
            if (text.length() > 0) {
                Arrays.fill(text.toCharArray(), '\0');
            }
        }
*/
        sendResult(intent, success, result);
    }

    private void sendResult(Intent intent, boolean success, String result) {
        Log.d(TAG, "📤 Enviando resultado: éxito=" + success + ", resultado=" + (result != null ? result.substring(0, Math.min(30, result.length())) + "..." : "null"));

        Bundle extras = intent.getExtras();
        Intent reply = new Intent("com.tuapp.CRYPTO_RESULT");
        reply.putExtra(EXTRA_SUCCESS, success);
        if (success && result != null) {
            reply.putExtra(EXTRA_RESULT, result);
        } else {
            reply.putExtra(EXTRA_RESULT, result); // Puede ser error
        }
        if (extras != null) {
            reply.putExtras(extras); // Para mantener contexto
        }
        sendBroadcast(reply, "com.tuapp.permission.CRYPTO"); // Permiso opcional
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "Servicio destruido");
        super.onDestroy();
    }
}
