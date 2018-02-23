/*
 * Copyright (C) 2017-2018 Supasin Tatiyanupanwong
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package me.tatiyanupanwong.supasin.oss.android.imprint;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.support.annotation.NonNull;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import me.tatiyanupanwong.supasin.oss.android.imprint.domain.AuthenticationResponse;
import me.tatiyanupanwong.supasin.oss.android.imprint.domain.DecryptionResponse;
import me.tatiyanupanwong.supasin.oss.android.imprint.domain.EncryptionResponse;
import me.tatiyanupanwong.supasin.oss.android.imprint.domain.FingerprintResult;
import me.tatiyanupanwong.supasin.oss.android.imprint.exception.FingerprintAuthenticationException;
import me.tatiyanupanwong.supasin.oss.android.imprint.exception.FingerprintUnavailableException;

@TargetApi(23)
@SuppressLint("MissingPermission") // It is the caller's responsibility to handle permission
class ImprintImpl extends Imprint {
    private static final String NOT_CAPABLE =
            "Fingerprint authentication is not available on this device.";
    private static final String NO_PERMISSION =
            "Must have android.permission.USE_FINGERPRINT permission.";

    private static final String RECOGNIZE = "Fingerprint recognized.";
    private static final String NOT_RECOGNIZE = "Fingerprint not recognized. Try again.";

    private final FingerprintFramework mFramework;
    private CancellationSignal mCancellationSignal;
    private String mAlias;

    ImprintImpl(Context context) {
        mFramework = new FingerprintFramework(context);
        mAlias = context.getPackageName();
    }

    @Override
    public Imprint setAlias(@NonNull String cryptoAlias) {
        mAlias = cryptoAlias;
        return this;
    }

    @Override
    public boolean isAvailable() {
        return isFingerprintPermissionGranted()
                && isHardwareDetected()
                && hasEnrolledFingerprints();
    }

    @Override
    public void authenticate(@NonNull AuthenticationCallback callback) {
        if (isAvailable()) {
            createCancellationSignal();
            authenticateInternal(callback);
        } else {
            onNotAvailable(callback);
        }
    }

    @Override
    public void encrypt(@NonNull final String toEncrypt,
            @NonNull final EncryptionCallback callback) {
        if (isAvailable()) {
            createCancellationSignal();
            encryptInternal(toEncrypt, callback);
        } else {
            onNotAvailable(callback);
        }
    }

    @Override
    public void decrypt(@NonNull final String toDecrypt,
            @NonNull final DecryptionCallback callback) {
        if (isAvailable()) {
            createCancellationSignal();
            decryptInternal(toDecrypt, callback);
        } else {
            onNotAvailable(callback);
        }
    }

    @Override
    public void cancel() {
        if (mCancellationSignal != null) {
            mCancellationSignal.cancel();
            mCancellationSignal = null;
        }
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

    // Lint is being stupid. The nullability is being checked before accessing APIs.
    @SuppressWarnings("ConstantConditions")
    private void authenticateInternal(@NonNull AuthenticationCallback callback) {
        mFramework.getFingerprintManager()
                .authenticate(null,
                        mCancellationSignal,
                        0,
                        wrapNativeCallbackForAuthentication(callback),
                        null);
    }

    // Lint is being stupid. The nullability is being checked before accessing APIs.
    @SuppressWarnings("ConstantConditions")
    private void encryptInternal(@NonNull final String toEncrypt,
            @NonNull final EncryptionCallback callback) {
        EncryptionCipherTask.with(mAlias, new FingerprintCipherTask.Callback() {
            @Override
            public void onTaskSucceeded(Cipher cipher) {
                mFramework.getFingerprintManager()
                        .authenticate(new FingerprintManager.CryptoObject(cipher),
                                mCancellationSignal,
                                0,
                                wrapNativeCallbackForEncryption(toEncrypt, callback),
                                null);
            }

            @Override
            public void onTaskFailed(Throwable throwable) {
                callback.onEncryptionFailure(throwable);
            }
        }).execute();
    }

    // Lint is being stupid. The nullability is being checked before accessing APIs.
    @SuppressWarnings("ConstantConditions")
    private void decryptInternal(@NonNull final String toDecrypt,
            @NonNull final DecryptionCallback callback) {
        DecryptionCipherTask.with(mAlias, toDecrypt, new FingerprintCipherTask.Callback() {
            @Override
            public void onTaskSucceeded(Cipher cipher) {
                mFramework.getFingerprintManager()
                        .authenticate(new FingerprintManager.CryptoObject(cipher),
                                mCancellationSignal,
                                0,
                                wrapNativeCallbackForDecryption(toDecrypt, callback),
                                null);
            }

            @Override
            public void onTaskFailed(Throwable throwable) {
                callback.onDecryptionFailure(throwable);

            }
        }).execute();
    }

    private void createCancellationSignal() {
        cancel();
        mCancellationSignal = new CancellationSignal();
    }

    private void onNotAvailable(Object callback) {
        if (isFingerprintPermissionGranted()) {
            wrapUnavailableCallback(NOT_CAPABLE, callback);
        } else {
            wrapUnavailableCallback(NO_PERMISSION, callback);
        }
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
                        FingerprintResult.HELP,
                        helpString.toString()));
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                callback.onAuthenticationResponse(new AuthenticationResponse(
                        FingerprintResult.AUTHENTICATED,
                        RECOGNIZE));
            }

            @Override
            public void onAuthenticationFailed() {
                callback.onAuthenticationResponse(new AuthenticationResponse(
                        FingerprintResult.FAILED,
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
                        FingerprintResult.HELP,
                        helpString.toString()));
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                try {
                    callback.onEncryptionResponse(new EncryptionResponse(
                            FingerprintResult.AUTHENTICATED,
                            RECOGNIZE,
                            encryptString(result.getCryptoObject().getCipher(), toEncrypt)));
                } catch (Exception e) {
                    callback.onEncryptionFailure(e);
                }
            }

            @Override
            public void onAuthenticationFailed() {
                callback.onEncryptionResponse(new EncryptionResponse(
                        FingerprintResult.FAILED,
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
                        FingerprintResult.HELP,
                        helpString.toString()));
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                try {
                    callback.onDecryptionResponse(new DecryptionResponse(
                            FingerprintResult.AUTHENTICATED,
                            RECOGNIZE,
                            decryptString(result.getCryptoObject().getCipher(), toDecrypt)));
                } catch (Exception e) {
                    callback.onDecryptionFailure(e);
                }
            }

            @Override
            public void onAuthenticationFailed() {
                callback.onDecryptionResponse(new DecryptionResponse(
                        FingerprintResult.FAILED,
                        NOT_RECOGNIZE));
            }
        };
    }

    private String encryptString(Cipher cipher, String initialText) throws Exception {
        byte[] encryptedBytes = cipher.doFinal(initialText.getBytes("UTF-8"));
        byte[] ivBytes = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

        String encryptedString = CryptoData.fromBytes(ivBytes, encryptedBytes).toString();
        CryptoData.verifyCryptoDataString(encryptedString);
        return encryptedString;
    }

    private String decryptString(Cipher cipher, String cipherText) throws Exception {
        CryptoData cryptoData = CryptoData.fromString(cipherText);
        return new String(cipher.doFinal(cryptoData.getMessage()));
    }
}
