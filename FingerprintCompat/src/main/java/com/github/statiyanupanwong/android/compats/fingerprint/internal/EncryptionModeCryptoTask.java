package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import android.hardware.fingerprint.FingerprintManager;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class EncryptionModeCryptoTask extends FingerprintCryptoTask {
    private final EncryptionTaskCallback mCallback;

    public static EncryptionModeCryptoTask with(String alias, EncryptionTaskCallback callback) {
        return new EncryptionModeCryptoTask(alias, callback);
    }

    private EncryptionModeCryptoTask(String alias, EncryptionTaskCallback callback) {
        super(alias);
        mCallback = callback;
    }

    @Override
    void initCipher(Cipher cipher, SecretKey secretKey) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }

    @Override
    void onCryptoTaskSucceeded(FingerprintManager.CryptoObject cryptoObject) {
        mCallback.onEncryptionTaskSucceeded(cryptoObject);
    }

    @Override
    void onCryptoTaskFailed(Throwable throwable) {
        mCallback.onEncryptionTaskFailed(throwable);
    }

    public interface EncryptionTaskCallback {
        void onEncryptionTaskSucceeded(FingerprintManager.CryptoObject cryptoObject);

        void onEncryptionTaskFailed(Throwable throwable);
    }
}
