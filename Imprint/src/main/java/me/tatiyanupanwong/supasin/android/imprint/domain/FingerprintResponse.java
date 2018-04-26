package me.tatiyanupanwong.supasin.android.imprint.domain;

abstract class FingerprintResponse {
    private final FingerprintResult mResult;
    private final String mMessage;

    FingerprintResponse(FingerprintResult result, String message) {
        mResult = result;
        mMessage = message;
    }

    public FingerprintResult getResult() {
        return mResult;
    }

    public String getMessage() {
        return mMessage;
    }
}
