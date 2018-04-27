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

package me.tatiyanupanwong.supasin.android.imprint;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import me.tatiyanupanwong.supasin.android.imprint.domain.AuthenticationResponse;
import me.tatiyanupanwong.supasin.android.imprint.domain.DecryptionResponse;
import me.tatiyanupanwong.supasin.android.imprint.domain.EncryptionResponse;
import me.tatiyanupanwong.supasin.android.imprint.domain.FingerprintResult;

/**
 * @author Supasin Tatiyanupanwong
 */
@SuppressWarnings({ "WeakerAccess", "unused" }) // Public API
public abstract class Imprint {
    Imprint() {}

    /**
     * Get a {@link Imprint.Impl} instance for a provided {@code context}.
     */
    @CheckResult
    public static Imprint from(@NonNull Context context) {
        return new Impl(context);
    }

    /**
     * Set name of the key in the keystore to use
     */
    @CheckResult
    public abstract Imprint setAlias(@NonNull String alias);

    /**
     * Check availability of fingerprint authentication.
     *
     * @return {@code true} if fingerprint authentication is available.
     */
    public abstract boolean isAvailable();

    /**
     * Authenticate the user with his/her fingerprint.
     */
    public abstract void authenticate(@NonNull AuthenticationCallback callback);

    /**
     * Encrypt data and authenticate the user with his/her fingerprint. All encrypted data can
     * only be accessed again by calling {@link Imprint#decrypt(String, DecryptionCallback)}
     */
    public abstract void encrypt(@NonNull String toEncrypt, @NonNull EncryptionCallback callback);

    /**
     * Decrypt data previously encrypted with {@link Imprint#encrypt(String, EncryptionCallback)}.
     */
    public abstract void decrypt(@NonNull String toDecrypt, @NonNull DecryptionCallback callback);

    /**
     * Cancel an existing fingerprint operation on this {@link Imprint} object.
     * Note that this must be called before {@link android.app.Activity#onPause()}
     */
    public abstract void cancel();

    /**
     * Interface definition for a callback of {@link Imprint#authenticate}. Users must provide an
     * implementation of this for listening to fingerprint events. One and only one method will be
     * invoked at a given time.
     */
    public interface AuthenticationCallback {
        /**
         * Invoked for a success or recoverable operation.
         */
        void onAuthenticationResponse(@NonNull AuthenticationResponse response);

        /**
         * Invoked for a failure operation.
         */
        void onAuthenticationFailure(@NonNull Throwable throwable);
    }

    /**
     * Interface definition for a callback of {@link Imprint#encrypt(String, EncryptionCallback)}.
     * Users must provide an implementation of this for listening to fingerprint events. One and
     * only one method will be invoked at a given time.
     */
    public interface EncryptionCallback {
        /**
         * Invoked for a success or recoverable operation.
         */
        void onEncryptionResponse(@NonNull EncryptionResponse response);

        /**
         * Invoked for a failure operation.
         */
        void onEncryptionFailure(@NonNull Throwable throwable);
    }

    /**
     * Interface definition for a callback of {@link Imprint#decrypt(String, DecryptionCallback)}.
     * Users must provide an implementation of this for listening to fingerprint events. One and
     * only one method will be invoked at a given time.
     */
    public interface DecryptionCallback {
        /**
         * Invoked for a success or recoverable operation.
         */
        void onDecryptionResponse(@NonNull DecryptionResponse response);

        /**
         * Invoked for a failure operation.
         */
        void onDecryptionFailure(@NonNull Throwable throwable);
    }


    @TargetApi(23)
    @SuppressLint("MissingPermission") // It is the caller's responsibility to handle permission
    static class Impl extends Imprint {
        // TODO: Localize these messages
        private static final String NOT_CAPABLE =
                "Fingerprint authentication is not available on this device.";
        private static final String NO_PERMISSION =
                "Must have android.permission.USE_FINGERPRINT permission.";

        private static final String RECOGNIZE = "Fingerprint recognized.";
        private static final String NOT_RECOGNIZE = "Fingerprint not recognized. Try again.";

        private final FingerprintFramework mFramework;
        private CancellationSignal mCancellationSignal;
        private String mAlias;

        Impl(@NonNull Context context) {
            mFramework = new FingerprintFramework(context);
            mAlias = context.getPackageName();
        }

        @CheckResult
        @Override
        public Imprint setAlias(@NonNull String cryptoAlias) {
            mAlias = cryptoAlias;
            return this;
        }

        @Override
        public boolean isAvailable() {
            return mFramework.isHardwareDetected() && mFramework.hasEnrolledFingerprints();
        }

        @Override
        public void authenticate(@NonNull AuthenticationCallback callback) {
            if (isAvailable()) {
                createCancellationSignal();
                authenticateInternal(callback);
            } else {
                wrapUnavailableCallback(NO_PERMISSION, callback);
            }
        }

        @Override
        public void encrypt(@NonNull String toEncrypt, @NonNull EncryptionCallback callback) {
            if (isAvailable()) {
                createCancellationSignal();
                encryptInternal(toEncrypt, callback);
            } else {
                wrapUnavailableCallback(NO_PERMISSION, callback);
            }
        }

        @Override
        public void decrypt(@NonNull String toDecrypt, @NonNull DecryptionCallback callback) {
            if (isAvailable()) {
                createCancellationSignal();
                decryptInternal(toDecrypt, callback);
            } else {
                wrapUnavailableCallback(NO_PERMISSION, callback);
            }
        }

        @Override
        public void cancel() {
            if (mCancellationSignal != null) {
                mCancellationSignal.cancel();
                mCancellationSignal = null;
            }
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

        private void wrapUnavailableCallback(String defMsg, Object callback) {
            if (callback instanceof AuthenticationCallback) {
                ((AuthenticationCallback) callback).onAuthenticationFailure(
                        new UnavailableException(defMsg));
            } else if (callback instanceof DecryptionCallback) {
                ((DecryptionCallback) callback).onDecryptionFailure(
                        new UnavailableException(defMsg));
            } else if (callback instanceof EncryptionCallback) {
                ((EncryptionCallback) callback).onEncryptionFailure(
                        new UnavailableException(defMsg));
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
                    callback.onAuthenticationFailure(
                            new AuthenticationException(errString));
                }

                @Override
                public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                    callback.onAuthenticationResponse(new AuthenticationResponse(
                            FingerprintResult.HELP, helpString.toString()));
                }

                @Override
                public void onAuthenticationSucceeded(
                        FingerprintManager.AuthenticationResult result) {
                    callback.onAuthenticationResponse(new AuthenticationResponse(
                            FingerprintResult.AUTHENTICATED, RECOGNIZE));
                }

                @Override
                public void onAuthenticationFailed() {
                    callback.onAuthenticationResponse(new AuthenticationResponse(
                            FingerprintResult.FAILED, NOT_RECOGNIZE));
                }
            };
        }

        private FingerprintManager.AuthenticationCallback wrapNativeCallbackForEncryption(
                final String toEncrypt, final EncryptionCallback callback) {
            return new FingerprintManager.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    callback.onEncryptionFailure(new AuthenticationException(errString));
                }

                @Override
                public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                    callback.onEncryptionResponse(new EncryptionResponse(FingerprintResult.HELP,
                            helpString.toString()));
                }

                @Override
                public void onAuthenticationSucceeded(
                        FingerprintManager.AuthenticationResult result) {
                    try {
                        callback.onEncryptionResponse(new EncryptionResponse(
                                FingerprintResult.AUTHENTICATED, RECOGNIZE,
                                encryptString(result.getCryptoObject().getCipher(), toEncrypt)));
                    } catch (Exception e) {
                        callback.onEncryptionFailure(e);
                    }
                }

                @Override
                public void onAuthenticationFailed() {
                    callback.onEncryptionResponse(new EncryptionResponse(FingerprintResult.FAILED,
                            NOT_RECOGNIZE));
                }
            };
        }

        private FingerprintManager.AuthenticationCallback wrapNativeCallbackForDecryption(
                final String toDecrypt, final DecryptionCallback callback) {
            return new FingerprintManager.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    callback.onDecryptionFailure(new AuthenticationException(errString));
                }

                @Override
                public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                    callback.onDecryptionResponse(new DecryptionResponse(FingerprintResult.HELP,
                            helpString.toString()));
                }

                @Override
                public void onAuthenticationSucceeded(
                        FingerprintManager.AuthenticationResult result) {
                    try {
                        callback.onDecryptionResponse(new DecryptionResponse(
                                FingerprintResult.AUTHENTICATED, RECOGNIZE,
                                decryptString(result.getCryptoObject().getCipher(), toDecrypt)));
                    } catch (Exception e) {
                        callback.onDecryptionFailure(e);
                    }
                }

                @Override
                public void onAuthenticationFailed() {
                    callback.onDecryptionResponse(new DecryptionResponse(FingerprintResult.FAILED,
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

    static class CryptoDataException extends Exception {
        private static final long serialVersionUID = 4221132514876868396L;
        private static final String ERR_MSG = "Invalid input given for decryption operation.";

        CryptoDataException() {
            super(ERR_MSG);
        }
    }

    public static class AuthenticationException extends Exception {
        private static final long serialVersionUID = -1134223020407641595L;

        AuthenticationException(CharSequence errString) {
            super(errString.toString());
        }
    }

    public static class UnavailableException extends Exception {
        private static final long serialVersionUID = -7106965054150661182L;

        UnavailableException(CharSequence errString) {
            super(errString.toString());
        }
    }
}
