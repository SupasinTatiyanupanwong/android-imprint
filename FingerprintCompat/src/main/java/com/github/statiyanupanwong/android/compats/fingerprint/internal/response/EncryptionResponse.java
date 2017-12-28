package com.github.statiyanupanwong.android.compats.fingerprint.internal.response;

import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintResponse;

public final class EncryptionResponse extends FingerprintResponse {
    private final String mEncrypted;

    public EncryptionResponse(FingerprintResult result, String message, String encrypted) {
        super(result, message);
        mEncrypted = encrypted;
    }

    @Override
    public String getData() {
        if (!isSuccessful()) {
            throw new IllegalStateException(
                    "Fingerprint authentication unsuccessful, cannot access encrypted data.");
        }
        return mEncrypted;
    }
}
