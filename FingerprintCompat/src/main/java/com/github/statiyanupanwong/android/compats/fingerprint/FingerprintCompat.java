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

import android.content.Context;
import android.support.annotation.NonNull;

public abstract class FingerprintCompat implements FingerprintCompatInterface {
    public static FingerprintCompat of(@NonNull Context context) {
        return new FingerprintCompatImpl(context);
    }

    public static boolean isAvailable(@NonNull Context context) {
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
    public void authenticate(@NonNull AuthenticationCallback callback) {
        authenticateImpl(callback);
    }

    @Override
    public void encrypt(@NonNull String toEncrypt, @NonNull EncryptionCallback callback) {
        encryptImpl(toEncrypt, callback);
    }

    @Override
    public void decrypt(@NonNull String toDecrypt, @NonNull DecryptionCallback callback) {
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
