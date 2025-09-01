package com.portafolio.key_vault_cipher.Vault.Core.Model;

public class EncryptedResult {
    public final String packagedDataBase64;
    public final String encryptedAESKeyBase64;

    public EncryptedResult(String packagedDataBase64, String encryptedAESKeyBase64) {
        this.packagedDataBase64 = packagedDataBase64;
        this.encryptedAESKeyBase64 = encryptedAESKeyBase64;
    }
}

