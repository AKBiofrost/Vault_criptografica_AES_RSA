package com.portafolio.key_vault_cipher.Vault.utiles;

import com.portafolio.key_vault_cipher.Vault.Core.Exception.EncryptionException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;

public class EncryptionUtils {

    public static void handleEncryptionError(Exception e) throws EncryptionException {
        if (e instanceof BadPaddingException || e instanceof AEADBadTagException) {
            throw EncryptionException.authenticationError("Error de autenticación - datos corruptos o modificados", e);
        } else if (e instanceof InvalidKeyException) {
            throw EncryptionException.keyManagementError("Clave inválida o no encontrada", e);
        } else if (e instanceof IllegalArgumentException || e instanceof IOException) {
            throw EncryptionException.formatError("Formato de datos incorrecto", e);
        } else if (e instanceof NoSuchAlgorithmException || e instanceof NoSuchPaddingException) {
            throw EncryptionException.encryptionError("Algoritmo de cifrado no disponible", e);
        } else {
            throw EncryptionException.encryptionError("Error durante el proceso de cifrado/descifrado", e);
        }
    }

    public static String getFriendlyErrorMessage(EncryptionException e) {
        switch (e.getErrorType()) {
            case AUTHENTICATION_ERROR:
                return "Error de seguridad: los datos han sido modificados o están corruptos";
            case KEY_MANAGEMENT_ERROR:
                return "Error de claves: no se puede acceder a las claves de seguridad";
            case FORMAT_ERROR:
                return "Formato incorrecto: los datos no tienen el formato esperado";
            case ENCRYPTION_ERROR:
                return "Error al cifrar los datos";
            case DECRYPTION_ERROR:
                return "Error al descifrar los datos";
            default:
                return "Error desconocido en el proceso de cifrado";
        }
    }
}
