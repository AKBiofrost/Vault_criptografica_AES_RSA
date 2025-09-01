package com.portafolio.key_vault_cipher.Vault.Core.Exception;

public class EncryptionException extends Exception {

    private final ErrorType errorType;

    public enum ErrorType {
        ENCRYPTION_ERROR,
        DECRYPTION_ERROR,
        KEY_MANAGEMENT_ERROR,
        AUTHENTICATION_ERROR,
        FORMAT_ERROR,
        UNKNOWN_ERROR
    }

    // Constructores
    public EncryptionException(String message) {
        super(message);
        this.errorType = ErrorType.UNKNOWN_ERROR;
    }

    public EncryptionException(String message, ErrorType errorType) {
        super(message);
        this.errorType = errorType;
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
        this.errorType = ErrorType.UNKNOWN_ERROR;
    }

    public EncryptionException(String message, Throwable cause, ErrorType errorType) {
        super(message, cause);
        this.errorType = errorType;
    }

    public EncryptionException(Throwable cause) {
        super(cause);
        this.errorType = ErrorType.UNKNOWN_ERROR;
    }

    public EncryptionException(Throwable cause, ErrorType errorType) {
        super(cause);
        this.errorType = errorType;
    }

    // Métodos específicos
    public ErrorType getErrorType() {
        return errorType;
    }

    public boolean isAuthenticationError() {
        return errorType == ErrorType.AUTHENTICATION_ERROR;
    }

    public boolean isKeyManagementError() {
        return errorType == ErrorType.KEY_MANAGEMENT_ERROR;
    }

    public boolean isFormatError() {
        return errorType == ErrorType.FORMAT_ERROR;
    }

    // Métodos estáticos para crear excepciones específicas
    public static EncryptionException authenticationError(String message, Throwable cause) {
        return new EncryptionException(message, cause, ErrorType.AUTHENTICATION_ERROR);
    }

    public static EncryptionException authenticationError(String message) {
        return new EncryptionException(message, ErrorType.AUTHENTICATION_ERROR);
    }

    public static EncryptionException keyManagementError(String message, Throwable cause) {
        return new EncryptionException(message, cause, ErrorType.KEY_MANAGEMENT_ERROR);
    }

    public static EncryptionException formatError(String message, Throwable cause) {
        return new EncryptionException(message, cause, ErrorType.FORMAT_ERROR);
    }

    public static EncryptionException encryptionError(String message, Throwable cause) {
        return new EncryptionException(message, cause, ErrorType.ENCRYPTION_ERROR);
    }

    public static EncryptionException decryptionError(String message, Throwable cause) {
        return new EncryptionException(message, cause, ErrorType.DECRYPTION_ERROR);
    }

    @Override
    public String toString() {
        return "EncryptionException{" +
                "errorType=" + errorType +
                ", message=" + getMessage() +
                ", cause=" + (getCause() != null ? getCause().getMessage() : "null") +
                '}';
    }
}
