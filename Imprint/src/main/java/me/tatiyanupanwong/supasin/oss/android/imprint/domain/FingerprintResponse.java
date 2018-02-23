package me.tatiyanupanwong.supasin.oss.android.imprint.domain;

import android.support.annotation.NonNull;

abstract class FingerprintResponse {
    private final FingerprintResult mResult;
    private final String mMessage;

    FingerprintResponse(@NonNull FingerprintResult result, @NonNull String message) {
        mResult = result;
        mMessage = message;
    }

    @NonNull
    public FingerprintResult getResult() {
        return mResult;
    }

    @NonNull
    public String getMessage() {
        return mMessage;
    }
}
