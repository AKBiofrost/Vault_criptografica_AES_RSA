package com.portafolio.key_vault_cipher.Vault.service;

import android.app.IntentService;
import android.content.Intent;
import android.util.Log;

import com.portafolio.key_vault_cipher.Vault.Core.HybridCryptoHelper;

public class CryptoIntentService extends IntentService {
    public static final String ACTION_ENCRYPT = "ENCRYPT";
    public static final String ACTION_DECRYPT = "DECRYPT";
    public static final String EXTRA_TEXT = "text";
    public static final String EXTRA_UUID = "uuid";
    public static final String EXTRA_IVPARAM = "ivparam";
    public static final String EXTRA_RESULT = "result";

    private HybridCryptoHelper cryptoHelper;

    public CryptoIntentService() {
        super("CryptoIntentService");
    }

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            cryptoHelper = new HybridCryptoHelper();
        } catch (Exception e) {
            Log.e("CryptoIntentService", "Error inicializando", e);
        }
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        if (intent != null) {
            String action = intent.getAction();
            Intent resultIntent = new Intent(action);

            try {
                if (ACTION_ENCRYPT.equals(action)) {
                    String text = intent.getStringExtra(EXTRA_TEXT);
                    String uuid = intent.getStringExtra(EXTRA_UUID);
                    String ivparam = intent.getStringExtra(EXTRA_IVPARAM);

                    String result = String.valueOf(cryptoHelper.encrypt(text, uuid, ivparam));
                    resultIntent.putExtra(EXTRA_RESULT, result);

                } else if (ACTION_DECRYPT.equals(action)) {
                    String encryptedText = intent.getStringExtra(EXTRA_TEXT);
                   // String result = cryptoHelper.(encryptedText);
                    resultIntent.putExtra(EXTRA_RESULT, "result");
                }

            } catch (Exception e) {
                resultIntent.putExtra(EXTRA_RESULT, "Error: " + e.getMessage());
            }

            // Enviar broadcast con resultado
            sendBroadcast(resultIntent);
        }
    }
}
