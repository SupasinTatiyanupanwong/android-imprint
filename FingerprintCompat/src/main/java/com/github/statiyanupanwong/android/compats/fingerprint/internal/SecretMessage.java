package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import android.util.Base64;

public final class SecretMessage {
    private static final String SEPARATOR = ",";

    private final String mEncodedIv;
    private final String mEncodedMessage;

    private SecretMessage(String iv, String message) {
        mEncodedIv = iv;
        mEncodedMessage = message;
    }

    public static SecretMessage fromString(String input) {
        verifySecretMessageString(input);

        String[] inputParams = input.split(SEPARATOR);
        return new SecretMessage(inputParams[0], inputParams[1]);
    }

    private static void verifySecretMessageString(String input) {
        if (input.isEmpty() || !input.contains(SEPARATOR)) {
            throw new IllegalArgumentException("Invalid input given for decryption operation.");
        }
    }

    @Override
    public String toString() {
        return mEncodedIv + SEPARATOR + mEncodedMessage;
    }

    public byte[] getIv() {
        return decode(mEncodedIv);
    }

    public byte[] getMessage() {
        return decode(mEncodedMessage);
    }

    private String encode(byte[] toEncode) {
        return Base64.encodeToString(toEncode, Base64.DEFAULT);
    }

    private byte[] decode(String toDecode) {
        return Base64.decode(toDecode, Base64.DEFAULT);
    }
}
