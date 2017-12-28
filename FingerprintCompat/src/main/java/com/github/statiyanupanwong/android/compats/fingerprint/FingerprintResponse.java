package com.github.statiyanupanwong.android.compats.fingerprint;

import android.support.annotation.NonNull;

public abstract class FingerprintResponse {
    private final FingerprintResult mResult;
    private final String mMessage;

    public FingerprintResponse(@NonNull FingerprintResult result, @NonNull String message) {
        mResult = result;
        mMessage = message;
    }

    public abstract String getData();

    @NonNull
    public FingerprintResult getResult() {
        return mResult;
    }

    @NonNull
    public String getMessage() {
        return mMessage;
    }

    public boolean isSuccessful() {
        return mResult == FingerprintResult.AUTHENTICATED;
    }

    public enum FingerprintResult {
        FAILED, HELP, AUTHENTICATED
    }
}
