package com.github.statiyanupanwong.android.compats.fingerprint.exception;

public class SecretMessageException extends Exception {
    private static final long serialVersionUID = 4221132514876868396L;
    private static final String ERR_MSG = "Invalid input given for decryption operation.";

    public SecretMessageException() {
        super(ERR_MSG);
    }
}
