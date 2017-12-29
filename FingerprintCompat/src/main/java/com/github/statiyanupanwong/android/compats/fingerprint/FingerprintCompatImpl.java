package com.github.statiyanupanwong.android.compats.fingerprint;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.util.Base64;

import com.github.statiyanupanwong.android.compats.fingerprint.exception.FingerprintAuthenticationException;
import com.github.statiyanupanwong.android.compats.fingerprint.exception.FingerprintUnavailableException;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.DecryptionModeCryptoTask;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.EncryptionModeCryptoTask;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.response.AuthenticationResponse;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.response.DecryptionResponse;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.response.EncryptionResponse;

import javax.crypto.Cipher;

@TargetApi(23)
@SuppressLint("MissingPermission")
class FingerprintCompatImpl extends FingerprintCompat {
    private static final String NOT_CAPABLE =
            "Fingerprint authentication is not available on this device.";
    private static final String NO_PERMISSION =
            "Must have android.permission.USE_FINGERPRINT permission.";

    private static final String RECOGNIZE = "Fingerprint recognized.";
    private static final String NOT_RECOGNIZE = "Fingerprint not recognized. Please try again.";

    private final FrameworkWrapper mFramework;
    private final CryptoAlgorithm mAlgorithm;
    private final String mAlias;

    FingerprintCompatImpl(Context context) {
        this(context, CryptoAlgorithm.AES);
    }

    FingerprintCompatImpl(Context context, CryptoAlgorithm algorithm) {
        mFramework = new FrameworkWrapper(context);
        mAlgorithm = algorithm;
        mAlias = context.getPackageName();
    }

    @Override
    void authenticateImpl(AuthenticationCallback callback) {
        if (checkPrecondition(callback)) {
            mFramework.getFingerprintManager()
                    .authenticate(null,
                            null,
                            0,
                            wrapNativeCallbackForAuthentication(callback),
                            null);
        }
    }

    @Override
    void encryptImpl(final String toEncrypt, final EncryptionCallback callback) {
        if (checkPrecondition(callback)) {
            EncryptionModeCryptoTask.with(mAlgorithm, mAlias)
                    .execute(new EncryptionModeCryptoTask.Callback() {
                        @Override
                        public void onCryptoTaskSucceeded(FingerprintManager.CryptoObject crypto) {
                            mFramework.getFingerprintManager().authenticate(crypto, null, 0,
                                    wrapNativeCallbackForEncryption(toEncrypt, callback), null);
                        }

                        @Override
                        public void onCryptoTaskFailed(Throwable throwable) {
                            callback.onEncryptionFailure(throwable);
                        }
                    });
        }
    }

    @Override
    void decryptImpl(final String toDecrypt, final DecryptionCallback callback) {
        if (checkPrecondition(callback)) {
            DecryptionModeCryptoTask.with(mAlgorithm, mAlias, toDecrypt)
                    .execute(new DecryptionModeCryptoTask.Callback() {
                        @Override
                        public void onCryptoTaskSucceeded(FingerprintManager.CryptoObject crypto) {
                            mFramework.getFingerprintManager().authenticate(crypto, null, 0,
                                    wrapNativeCallbackForDecryption(toDecrypt, callback), null);
                        }

                        @Override
                        public void onCryptoTaskFailed(Throwable throwable) {
                            callback.onDecryptionFailure(throwable);
                        }
                    });
        }
    }

    @Override
    boolean isAvailable() {
        return isFingerprintPermissionGranted()
                && isHardwareDetected()
                && hasEnrolledFingerprints();
    }

    @Override
    boolean isHardwareDetected() {
        return mFramework.isHardwareDetected();
    }

    @Override
    boolean hasEnrolledFingerprints() {
        return mFramework.hasEnrolledFingerprints();
    }

    @Override
    boolean isFingerprintPermissionGranted() {
        return mFramework.isFingerprintPermissionGranted();
    }

    private String encrypt(Cipher cipher, String initialText) throws Exception {
        byte[] bytes = cipher.doFinal(initialText.getBytes());
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }

    private String decrypt(Cipher cipher, String cipherText) throws Exception {
        byte[] bytes = Base64.decode(cipherText, Base64.NO_WRAP);
        return new String(cipher.doFinal(bytes));
    }

    private boolean checkPrecondition(Object callback) {
        if (!isAvailable()) {
            if (isFingerprintPermissionGranted()) {
                wrapUnavailableCallback(NOT_CAPABLE, callback);
            } else {
                wrapUnavailableCallback(NO_PERMISSION, callback);
            }
            return false;
        }
        return true;
    }

    private void wrapUnavailableCallback(String defMsg, Object callback) {
        if (callback instanceof AuthenticationCallback) {
            ((AuthenticationCallback) callback).onAuthenticationFailure(
                    new FingerprintUnavailableException(defMsg));
        } else if (callback instanceof DecryptionCallback) {
            ((DecryptionCallback) callback).onDecryptionFailure(
                    new FingerprintUnavailableException(defMsg));
        } else if (callback instanceof EncryptionCallback) {
            ((EncryptionCallback) callback).onEncryptionFailure(
                    new FingerprintUnavailableException(defMsg));
        } else {
            throw new RuntimeException(
                    "Unsupported callback type: " + callback.getClass().getSimpleName());
        }
    }

    private FingerprintManager.AuthenticationCallback wrapNativeCallbackForAuthentication(
            final AuthenticationCallback callback) {
        return new FingerprintManager.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                callback.onAuthenticationFailure(new FingerprintAuthenticationException(errString));
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                callback.onAuthenticationResponse(new AuthenticationResponse(
                        FingerprintResponse.FingerprintResult.HELP,
                        helpString.toString()));
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                callback.onAuthenticationResponse(new AuthenticationResponse(
                        FingerprintResponse.FingerprintResult.AUTHENTICATED,
                        RECOGNIZE));
            }

            @Override
            public void onAuthenticationFailed() {
                callback.onAuthenticationResponse(new AuthenticationResponse(
                        FingerprintResponse.FingerprintResult.FAILED,
                        NOT_RECOGNIZE));
            }
        };
    }

    private FingerprintManager.AuthenticationCallback wrapNativeCallbackForEncryption(
            final String toEncrypt, final EncryptionCallback callback) {
        return new FingerprintManager.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                callback.onEncryptionFailure(new FingerprintAuthenticationException(errString));
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                callback.onEncryptionResponse(new EncryptionResponse(
                        FingerprintResponse.FingerprintResult.HELP,
                        helpString.toString()));
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                try {
                    callback.onEncryptionResponse(new EncryptionResponse(
                            FingerprintResponse.FingerprintResult.AUTHENTICATED,
                            RECOGNIZE,
                            encrypt(result.getCryptoObject().getCipher(), toEncrypt)));
                } catch (Exception e) {
                    callback.onEncryptionFailure(e);
                }
            }

            @Override
            public void onAuthenticationFailed() {
                callback.onEncryptionResponse(new EncryptionResponse(
                        FingerprintResponse.FingerprintResult.FAILED,
                        NOT_RECOGNIZE));
            }
        };
    }

    private FingerprintManager.AuthenticationCallback wrapNativeCallbackForDecryption(
            final String toDecrypt, final DecryptionCallback callback) {
        return new FingerprintManager.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                callback.onDecryptionFailure(new FingerprintAuthenticationException(errString));
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                callback.onDecryptionResponse(new DecryptionResponse(
                        FingerprintResponse.FingerprintResult.HELP,
                        helpString.toString()));
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                try {
                    callback.onDecryptionResponse(new DecryptionResponse(
                            FingerprintResponse.FingerprintResult.AUTHENTICATED,
                            RECOGNIZE,
                            decrypt(result.getCryptoObject().getCipher(), toDecrypt)));
                } catch (Exception e) {
                    callback.onDecryptionFailure(e);
                }
            }

            @Override
            public void onAuthenticationFailed() {
                callback.onDecryptionResponse(new DecryptionResponse(
                        FingerprintResponse.FingerprintResult.FAILED,
                        NOT_RECOGNIZE));
            }
        };
    }
}
