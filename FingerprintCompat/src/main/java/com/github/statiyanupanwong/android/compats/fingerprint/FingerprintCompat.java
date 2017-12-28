package com.github.statiyanupanwong.android.compats.fingerprint;

import android.content.Context;

public abstract class FingerprintCompat implements FingerprintCompatInterface {
    public static FingerprintCompat with(Context context) {
        return new FingerprintCompatImpl(context);
    }

    public static boolean isAvailable(Context context) {
        return with(context).isAvailable();
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
