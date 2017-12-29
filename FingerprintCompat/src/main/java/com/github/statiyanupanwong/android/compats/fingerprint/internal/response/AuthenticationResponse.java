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

package com.github.statiyanupanwong.android.compats.fingerprint.internal.response;

import android.support.annotation.NonNull;

import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintResponse;

public final class AuthenticationResponse extends FingerprintResponse {
    public AuthenticationResponse(FingerprintResult result, String message) {
        super(result, message);
    }

    @NonNull
    @Override
    public String getData() {
        throw new IllegalStateException(
                "There is no requested cryptographic operations, data is not available.");
    }
}
