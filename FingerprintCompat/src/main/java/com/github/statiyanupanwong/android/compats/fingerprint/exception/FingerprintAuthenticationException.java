package com.github.statiyanupanwong.android.compats.fingerprint.exception;

public class FingerprintAuthenticationException extends Exception {
    private static final long serialVersionUID = -1134223020407641595L;

    public FingerprintAuthenticationException(CharSequence errString) {
        super(errString.toString());
    }
}
