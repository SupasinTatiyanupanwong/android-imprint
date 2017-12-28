package com.github.statiyanupanwong.android.compats.fingerprint.internal.response;

import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintResponse;

public final class AuthenticationResponse extends FingerprintResponse {
    public AuthenticationResponse(FingerprintResult result, String message) {
        super(result, message);
    }

    @Override
    public String getData() {
        throw new IllegalStateException(
                "There is no requested cryptographic operations, data is not available.");
    }
}
