package com.portafolio.key_vault_cipher.Vault.utiles;

import android.content.Context;
import android.content.SharedPreferences;

public class SecurePreferences {
    private static final String PREFS = "secure_prefs";
    private static final String SALT = "salt_key";

    public static void saveSalt(Context ctx, byte[] salt) {
        SharedPreferences sp = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        sp.edit().putString(SALT, android.util.Base64.encodeToString(salt, android.util.Base64.NO_WRAP)).apply();
    }

    public static byte[] getSalt(Context ctx) {
        SharedPreferences sp = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String enc = sp.getString(SALT, null);
        return enc != null ? android.util.Base64.decode(enc, android.util.Base64.NO_WRAP) : null;
    }
}
