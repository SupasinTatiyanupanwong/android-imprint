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

import android.content.Context;
import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;

import me.tatiyanupanwong.supasin.oss.android.imprint.domain.AuthenticationResponse;
import me.tatiyanupanwong.supasin.oss.android.imprint.domain.DecryptionResponse;
import me.tatiyanupanwong.supasin.oss.android.imprint.domain.EncryptionResponse;

public abstract class Imprint implements ImprintInterface {
    Imprint() {}

    @CheckResult
    public static Imprint of(@NonNull Context context) {
        return new ImprintImpl(context);
    }

    @CheckResult
    @Override
    public abstract Imprint setAlias(@NonNull String alias);

    @Override
    public abstract boolean isAvailable();

    @Override
    public abstract void authenticate(@NonNull AuthenticationCallback callback);

    @Override
    public abstract void encrypt(@NonNull String toEncrypt, @NonNull EncryptionCallback callback);

    @Override
    public abstract void decrypt(@NonNull String toDecrypt, @NonNull DecryptionCallback callback);

    /**
     * Cancel an existing fingerprint operation on this {@link Imprint} object.
     * Note that this must be called before {@link android.app.Activity#onPause()}
     */
    @Override
    public abstract void cancel();

    abstract boolean isHardwareDetected();

    abstract boolean hasEnrolledFingerprints();

    abstract boolean isFingerprintPermissionGranted();

    public interface AuthenticationCallback {
        void onAuthenticationResponse(@NonNull AuthenticationResponse response);

        void onAuthenticationFailure(@NonNull Throwable throwable);
    }

    public interface DecryptionCallback {
        void onDecryptionResponse(@NonNull DecryptionResponse response);

        void onDecryptionFailure(@NonNull Throwable throwable);
    }

    public interface EncryptionCallback {
        void onEncryptionResponse(@NonNull EncryptionResponse response);

        void onEncryptionFailure(@NonNull Throwable throwable);
    }
}
