package com.github.statiyanupanwong.android.compats.fingerprint;

import android.content.Context;

public abstract class FingerprintCompat implements FingerprintCompatInterface {
    public static FingerprintCompat of(Context context) {
        return new FingerprintCompatImpl(context);
    }

    public static boolean isAvailable(Context context) {
        return of(context).isAvailable();
    }

    abstract boolean isAvailable();

    abstract boolean isHardwareDetected();

    abstract boolean hasEnrolledFingerprints();

    abstract boolean isFingerprintPermissionGranted();

    abstract void authenticateImpl(AuthenticationCallback callback);

    abstract void encryptImpl(String toEncrypt, EncryptionCallback callback);

    abstract void decryptImpl(String toDecrypt, DecryptionCallback callback);

    @Override
    public void authenticate(AuthenticationCallback callback) {
        authenticateImpl(callback);
    }

    @Override
    public void encrypt(String toEncrypt, EncryptionCallback callback) {
        encryptImpl(toEncrypt, callback);
    }

    @Override
    public void decrypt(String toDecrypt, DecryptionCallback callback) {
        decryptImpl(toDecrypt, callback);
    }

    public interface AuthenticationCallback {
        void onAuthenticationResponse(FingerprintResponse response);

        void onAuthenticationFailure(Throwable throwable);
    }

    public interface DecryptionCallback {
        void onDecryptionResponse(FingerprintResponse response);

        void onDecryptionFailure(Throwable throwable);
    }

    public interface EncryptionCallback {
        void onEncryptionResponse(FingerprintResponse response);

        void onEncryptionFailure(Throwable throwable);
    }
}
