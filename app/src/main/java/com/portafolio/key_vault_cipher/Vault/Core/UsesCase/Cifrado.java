package com.portafolio.key_vault_cipher.Vault.Core.UsesCase;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.lifecycle.LifecycleOwner;
import androidx.work.Data;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;

import com.portafolio.key_vault_cipher.Vault.Core.CryptoWorker;
import com.portafolio.key_vault_cipher.Vault.Core.Exception.EncryptionException;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class Cifrado {
    private static Cifrado instance;
    private static Context contextT;

    public static synchronized Cifrado getInstance(Context context)  {
        if (instance == null) {
            contextT = context;
            instance = new Cifrado();
        }
        return instance;
    }

    private synchronized boolean cifrarTexto(@NonNull String data, @NonNull String UUID, @NonNull String seed) {
        AtomicBoolean resultT = new AtomicBoolean(false);
        Data inputData = new Data.Builder()
                .putString(CryptoWorker.ACTION, CryptoWorker.ENCRYPT)
                .putString(CryptoWorker.TEXT, data)
                .putString(CryptoWorker.UUID, UUID)
                .putString(CryptoWorker.IVPARAM, seed)
                .build();

        OneTimeWorkRequest work = new OneTimeWorkRequest.Builder(CryptoWorker.class)
                .setInputData(inputData)
                .build();

        WorkManager.getInstance(contextT).enqueue(work);

        WorkManager.getInstance(contextT).getWorkInfoByIdLiveData(work.getId())
                .observe((LifecycleOwner) contextT, info -> {
                    if (info != null && info.getState().isFinished()) {
                        Data output = info.getOutputData();
                        boolean success = Boolean.parseBoolean(output.getString(CryptoWorker.SUCCESS));
                        String result = output.getString(CryptoWorker.RESULT);

                        if (success && !result.equals("null")) {
                            //tv.append("\n✅ Cifrado: " + result.substring(0, 50) + "...");
                            resultT.set(true);
                        } else {
                            resultT.set(false);
                        }
                    }

                });
        return resultT.get();
    }


    private synchronized String descifrarTextoConWorker() {
        AtomicReference<String> resultT = new AtomicReference<>("");

        // Crear datos de entrada
        Data inputData = new Data.Builder()
                .putString(CryptoWorker.ACTION, CryptoWorker.DECRYPT)
                .putString(CryptoWorker.TEXT, "safeEncrypted")
                .build();

        // Crear trabajo
        OneTimeWorkRequest work = new OneTimeWorkRequest.Builder(CryptoWorker.class)
                .setInputData(inputData)
                .build();

        // Enqueue
        WorkManager.getInstance(contextT).enqueue(work);

        // Observar resultado
        WorkManager.getInstance(contextT).getWorkInfoByIdLiveData(work.getId())
                .observe((LifecycleOwner) contextT, workInfo -> {
                    if (workInfo != null && workInfo.getState().isFinished()) {
                        Data outputData = workInfo.getOutputData();
                        boolean success = Boolean.parseBoolean(outputData.getString(CryptoWorker.SUCCESS));
                        String result = outputData.getString(CryptoWorker.RESULT);

                        if (success && !"null".equals(result)) {
                            resultT.set(result);
                        } else {
                            resultT.set("Fallido");
                        }
                    }
                });

        return resultT.get();
    }

}
