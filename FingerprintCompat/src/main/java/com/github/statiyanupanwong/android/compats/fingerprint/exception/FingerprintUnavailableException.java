package com.github.statiyanupanwong.android.compats.fingerprint.exception;

public class FingerprintUnavailableException extends Exception {
    private static final long serialVersionUID = -7106965054150661182L;

    public FingerprintUnavailableException(CharSequence errString) {
        super(errString.toString());
    }
}
