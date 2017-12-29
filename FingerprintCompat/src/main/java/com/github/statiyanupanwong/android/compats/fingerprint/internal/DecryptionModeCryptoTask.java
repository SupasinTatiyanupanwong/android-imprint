package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import android.hardware.fingerprint.FingerprintManager;

import com.github.statiyanupanwong.android.compats.fingerprint.exception.SecretMessageException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class DecryptionModeCryptoTask extends FingerprintCryptoTask {
    private final SecretMessage mSecretMessage;
    private final DecryptionTaskCallback mCallback;

    public static DecryptionModeCryptoTask with(String alias, String secretMessage,
            DecryptionTaskCallback callback) throws SecretMessageException {
        return new DecryptionModeCryptoTask(alias, secretMessage, callback);
    }

    private DecryptionModeCryptoTask(String alias, String secretMessage,
            DecryptionTaskCallback callback) throws SecretMessageException {
        super(alias);
        mSecretMessage = SecretMessage.fromString(secretMessage);
        mCallback = callback;
    }

    @Override
    void initCipher(Cipher cipher, SecretKey secretKey) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(mSecretMessage.getIv()));
    }

    @Override
    void onCryptoTaskSucceeded(FingerprintManager.CryptoObject cryptoObject) {
        mCallback.onDecryptionTaskSucceeded(cryptoObject);
    }

    @Override
    void onCryptoTaskFailed(Throwable throwable) {
        mCallback.onDecryptionTaskFailed(throwable);
    }

    public interface DecryptionTaskCallback {
        void onDecryptionTaskSucceeded(FingerprintManager.CryptoObject cryptoObject);

        void onDecryptionTaskFailed(Throwable throwable);
    }
}
