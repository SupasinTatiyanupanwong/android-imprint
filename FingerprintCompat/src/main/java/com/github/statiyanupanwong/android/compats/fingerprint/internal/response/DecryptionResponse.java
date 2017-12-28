package com.github.statiyanupanwong.android.compats.fingerprint.internal.response;

import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintResponse;

public final class DecryptionResponse extends FingerprintResponse {
    private final String mDecrypted;

    public DecryptionResponse(FingerprintResult result, String message, String decrypted) {
        super(result, message);
        mDecrypted = decrypted;
    }

    @Override
    public String getData() {
        if (!isSuccessful()) {
            throw new IllegalStateException(
                    "Fingerprint authentication unsuccessful, cannot access decrypted data.");
        }
        return mDecrypted;
    }
}
