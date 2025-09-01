package com.portafolio.key_vault_cipher.Vault.Api;


import android.annotation.SuppressLint;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import android.util.Log;
import android.widget.TextView;

import androidx.work.Data;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;

import com.portafolio.key_vault_cipher.Vault.Core.CryptoWorker;

public class MainActivity extends AppCompatActivity {

    private TextView tv;
    private String encryptedText = null; // Para guardar temporalmente el texto cifrado


    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        tv = new TextView(this);
        tv.setPadding(40, 40, 40, 40);
        tv.setText("🚀 Iniciando prueba de cifrado/descifrado...\n");
        setContentView(tv);
        Log.d("MainActivity", "mPid: " + android.os.Process.myPid());
        // Registrar el receptor
        // IntentFilter filter = new IntentFilter("com.tuapp.CRYPTO_RESULT");
        // registerReceiver(resultReceiver, filter);

        // === PASO 1: CIFRAR ===
        cifrarTexto("BUAJAJAJAJAJJAJAJAA; AHORA SI PERROS, TRIPLE CIFRADO HIPER SEGURO DAME LA CUCA DE TU HERMANA",
                "0123456789012345678901234567890123456789",
                "VTID");


    }



   /*
    private void cifrarTexto() {
        tv.append("\n🔄 Cifrando directamente en hilo...");

        new Thread(() -> {
            try {
                HybridCryptoHelper crypto = new HybridCryptoHelper();
                crypto.generateRSAKeyPair();
                String encrypted = crypto.encrypt("Mensaje de prueba");
                runOnUiThread(() -> {
                    if (encrypted != null) {
                        tv.append("\n✅ Cifrado: " + encrypted.substring(0, 50) + "...");
                        encryptedText = encrypted;
                        descifrarTexto();
                    } else {
                        tv.append("\n❌ Cifrado devolvió null");
                    }
                });
            } catch (Exception e) {
                Log.e("DirectCrypto", "Error", e);
                runOnUiThread(() -> tv.append("\n❌ Error: " + e.getMessage()));
            }
        }).start();
    }
*/

    private void cifrarTexto( String data, String UUID, String seed) {
        tv.append("\n🔄 Cifrando con WorkManager...");

        Data inputData = new Data.Builder()
                .putString(CryptoWorker.ACTION, CryptoWorker.ENCRYPT)
                .putString(CryptoWorker.TEXT, data)
                .putString(CryptoWorker.UUID, UUID)
                .putString(CryptoWorker.IVPARAM, seed)
                .build();

        OneTimeWorkRequest work = new OneTimeWorkRequest.Builder(CryptoWorker.class)
                .setInputData(inputData)
                .build();

        WorkManager.getInstance(this).enqueue(work);

        WorkManager.getInstance(this).getWorkInfoByIdLiveData(work.getId())
                .observe(this, info -> {
                    if (info != null && info.getState().isFinished()) {
                        Data output = info.getOutputData();
                        boolean success = Boolean.parseBoolean(output.getString(CryptoWorker.SUCCESS));
                        String result = output.getString(CryptoWorker.RESULT);

                        if (success && !result.equals("null")) {
                            //tv.append("\n✅ Cifrado: " + result.substring(0, 50) + "...");
                            tv.append("\n✅ Cifrado: " + result);
                            encryptedText = result;
                            descifrarTextoConWorker();
                        } else {
                            tv.append("\n❌ Error: " + result);
                        }
                    }
                });
    }


    /**
     * Inicia el descifrado usando el texto cifrado guardado
     */
    /*
    private void descifrarTexto() {
        if (encryptedText == null) {
            tv.append("\n⚠️ No hay texto cifrado para descifrar.");
            return;
        }
        // Depuración: muestra los primeros caracteres
        Log.d("MainActivity", "🔍 Texto cifrado a descifrar: " + encryptedText.substring(0, Math.min(50, encryptedText.length())) + "...");

        tv.append("\n🔄 Descifrando...");

        Intent intent = new Intent(this, SecureCryptoService.class);
        intent.putExtra(SecureCryptoService.EXTRA_ACTION, SecureCryptoService.ACTION_DECRYPT);
        intent.putExtra(SecureCryptoService.EXTRA_TEXT, encryptedText);
        intent.putExtra(SecureCryptoService.EXTRA_ACTION, SecureCryptoService.ACTION_DECRYPT); // Para identificar en el resultado

        SecureCryptoService.enqueueWork(this, intent);
    }
*/
    private void descifrarTextoConWorker() {
        if (encryptedText == null) {
            tv.append("\n❌ No hay texto cifrado para descifrar.");
            return;
        }

        tv.append("\n🔄 Descifrando con WorkManager...");

        // Asegurarnos de que no haya espacios o saltos extra
        String safeEncrypted = encryptedText.trim();

        // Crear datos de entrada
        Data inputData = new Data.Builder()
                .putString(CryptoWorker.ACTION, CryptoWorker.DECRYPT)
                .putString(CryptoWorker.TEXT, safeEncrypted)
                .build();

        // Crear trabajo
        OneTimeWorkRequest work = new OneTimeWorkRequest.Builder(CryptoWorker.class)
                .setInputData(inputData)
                .build();

        // Enqueue
        WorkManager.getInstance(this).enqueue(work);

        // Observar resultado
        WorkManager.getInstance(this).getWorkInfoByIdLiveData(work.getId())
                .observe(this, workInfo -> {
                    if (workInfo != null && workInfo.getState().isFinished()) {
                        Data outputData = workInfo.getOutputData();
                        boolean success = Boolean.parseBoolean(outputData.getString(CryptoWorker.SUCCESS));
                        String result = outputData.getString(CryptoWorker.RESULT);

                        if (success && !"null".equals(result)) {
                            tv.append("\n✅ Descifrado: " + result);
                        } else {
                            tv.append("\n❌ Error al descifrar: " + result);
                        }
                    }
                });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }


}