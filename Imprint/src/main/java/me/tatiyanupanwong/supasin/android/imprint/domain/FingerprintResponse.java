package me.tatiyanupanwong.supasin.android.imprint.domain;

import android.support.annotation.NonNull;

/**
 * @author Supasin Tatiyanupanwong
 */
abstract class FingerprintResponse {
    private final FingerprintResult mResult;
    private final String mMessage;

    FingerprintResponse(FingerprintResult result, String message) {
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
