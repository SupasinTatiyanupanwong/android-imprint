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

package me.tatiyanupanwong.supasin.android.imprint.domain;

import android.support.annotation.NonNull;

/**
 * @author Supasin Tatiyanupanwong
 */
public final class EncryptionResponse extends FingerprintResponse {
    private final String mEncrypted;

    public EncryptionResponse(FingerprintResult result, String message) {
        this(result, message, null);
    }

    public EncryptionResponse(FingerprintResult result, String message, String encrypted) {
        super(result, message);
        mEncrypted = encrypted;
    }

    @NonNull
    public String getEncrypted() {
        if (getResult() != FingerprintResult.AUTHENTICATED) {
            throw new IllegalStateException(
                    "Fingerprint authentication unsuccessful, cannot access encrypted data.");
        }
        return mEncrypted;
    }
}
