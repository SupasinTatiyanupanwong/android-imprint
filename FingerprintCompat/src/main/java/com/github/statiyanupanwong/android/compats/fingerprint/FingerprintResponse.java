package com.github.statiyanupanwong.android.compats.fingerprint;

import android.support.annotation.NonNull;

public abstract class FingerprintResponse {
    private final FingerprintResult mResult;
    private final String mMessage;

    public FingerprintResponse(@NonNull FingerprintResult result, String message) {
        mResult = result;
        mMessage = message;
    }

    public FingerprintResult getResult() {
        return mResult;
    }

    public String getMessage() {
        return mMessage;
    }

    public boolean isSuccessful() {
        return mResult == FingerprintResult.AUTHENTICATED;
    }

    public abstract String getData();

    public enum FingerprintResult {
        FAILED, HELP, AUTHENTICATED
    }
}
