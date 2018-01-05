/*
 * Copyright (C) 2017 Supasin Tatiyanupanwong
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

package com.github.statiyanupanwong.android.compats.fingerprint;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.support.annotation.NonNull;

import com.github.statiyanupanwong.android.compats.fingerprint.exception.FingerprintAuthenticationException;
import com.github.statiyanupanwong.android.compats.fingerprint.exception.FingerprintUnavailableException;
import com.github.statiyanupanwong.android.compats.fingerprint.exception.SecretMessageException;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.DecryptionModeCryptoTask;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.EncryptionModeCryptoTask;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.SecretMessage;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.response.AuthenticationResponse;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.response.DecryptionResponse;
import com.github.statiyanupanwong.android.compats.fingerprint.internal.response.EncryptionResponse;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

@TargetApi(23)
@SuppressLint("MissingPermission")
class FingerprintCompatImpl extends FingerprintCompat {
    private static final String NOT_CAPABLE =
            "Fingerprint authentication is not available on this device.";
    private static final String NO_PERMISSION =
            "Must have android.permission.USE_FINGERPRINT permission.";

    private static final String RECOGNIZE = "Fingerprint recognized.";
    private static final String NOT_RECOGNIZE = "Fingerprint not recognized. Try again.";

    private final FrameworkWrapper mFramework;
    private CancellationSignal mCancellationSignal;
    private String mAlias;

    FingerprintCompatImpl(Context context) {
        mFramework = new FrameworkWrapper(context);
        mCancellationSignal = new CancellationSignal();
        mAlias = context.getPackageName();
    }

    @Override
    public FingerprintCompat setAlias(@NonNull String cryptoAlias) {
        mAlias = cryptoAlias;
        return this;
    }

    @Override
    public boolean isAvailable() {
        return isFingerprintPermissionGranted()
                && isHardwareDetected()
                && hasEnrolledFingerprints();
    }

    // Lint is being stupid. The nullability is being checked first before accessing APIs.
    @SuppressWarnings("ConstantConditions")
    @Override
    public void authenticate(@NonNull AuthenticationCallback callback) {
        if (isAvailable()) {
            mFramework.getFingerprintManager()
                    .authenticate(null,
                            mCancellationSignal,
                            0,
                            wrapNativeCallbackForAuthentication(callback),
                            null);
        } else {
            onNotAvailable(callback);
        }
    }

    // Lint is being stupid. The nullability is being checked first before accessing APIs.
    @SuppressWarnings("ConstantConditions")
    @Override
    public void encrypt(@NonNull final String toEncrypt,
            @NonNull final EncryptionCallback callback) {
        if (isAvailable()) {
            EncryptionModeCryptoTask.with(mAlias,
                    new EncryptionModeCryptoTask.EncryptionTaskCallback() {
                        @Override
                        public void onEncryptionTaskSucceeded(
                                FingerprintManager.CryptoObject cryptoObject) {
                            mFramework.getFingerprintManager().authenticate(cryptoObject,
                                    mCancellationSignal,
                                    0,
                                    wrapNativeCallbackForEncryption(toEncrypt, callback),
                                    null);
                        }

                        @Override
                        public void onEncryptionTaskFailed(Throwable throwable) {
                            callback.onEncryptionFailure(throwable);
                        }
                    }).execute();
        } else {
            onNotAvailable(callback);
        }
    }

    // Lint is being stupid. The nullability is being checked first before accessing APIs.
    @SuppressWarnings("ConstantConditions")
    @Override
    public void decrypt(@NonNull final String toDecrypt,
            @NonNull final DecryptionCallback callback) {
        if (isAvailable()) {
            try {
                DecryptionModeCryptoTask.with(mAlias, toDecrypt,
                        new DecryptionModeCryptoTask.DecryptionTaskCallback() {
                            @Override
                            public void onDecryptionTaskSucceeded(
                                    FingerprintManager.CryptoObject cryptoObject) {
                                mFramework.getFingerprintManager().authenticate(cryptoObject,
                                        mCancellationSignal,
                                        0,
                                        wrapNativeCallbackForDecryption(toDecrypt, callback),
                                        null);
                            }

                            @Override
                            public void onDecryptionTaskFailed(Throwable throwable) {
                                callback.onDecryptionFailure(throwable);

                            }
                        }).execute();
            } catch (SecretMessageException e) {
                callback.onDecryptionFailure(e);
            }
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
                            encryptString(result.getCryptoObject().getCipher(), toEncrypt)));
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
                            decryptString(result.getCryptoObject().getCipher(), toDecrypt)));
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

    private String encryptString(Cipher cipher, String initialText) throws Exception {
        byte[] encryptedBytes = cipher.doFinal(initialText.getBytes("UTF-8"));
        byte[] ivBytes =
                cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

        String encryptedString =
                SecretMessage.fromBytes(ivBytes, encryptedBytes).toString();
        SecretMessage.verifySecretMessageString(encryptedString);
        return encryptedString;
    }

    private String decryptString(Cipher cipher, String cipherText) throws Exception {
        SecretMessage secretMessage = SecretMessage.fromString(cipherText);
        return new String(cipher.doFinal(secretMessage.getMessage()));
    }
}
