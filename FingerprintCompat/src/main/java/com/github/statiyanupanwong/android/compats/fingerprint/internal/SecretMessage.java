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

package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import android.text.TextUtils;
import android.util.Base64;

import com.github.statiyanupanwong.android.compats.fingerprint.exception.SecretMessageException;

public final class SecretMessage {
    private static final String SEPARATOR = "::";

    private final String mEncodedIv;
    private final String mEncodedMessage;

    private SecretMessage(byte[] ivBytes, byte[] messageBytes) {
        mEncodedIv = encode(ivBytes);
        mEncodedMessage = encode(messageBytes);
    }

    private SecretMessage(String iv, String message) {
        mEncodedIv = iv;
        mEncodedMessage = message;
    }

    public static SecretMessage fromBytes(byte[] ivBytes, byte[] messageBytes) {
        return new SecretMessage(ivBytes, messageBytes);
    }

    public static SecretMessage fromString(String input) throws SecretMessageException {
        verifySecretMessageString(input);

        String[] inputParams = input.split(SEPARATOR);
        return new SecretMessage(inputParams[0], inputParams[1]);
    }

    public static void verifySecretMessageString(String input) throws SecretMessageException {
        if (TextUtils.isEmpty(input) || !input.contains(SEPARATOR)) {
            throw new SecretMessageException();
        }
    }

    @Override
    public String toString() {
        return mEncodedIv + SEPARATOR + mEncodedMessage;
    }

    byte[] getIv() {
        return decode(mEncodedIv);
    }

    public byte[] getMessage() {
        return decode(mEncodedMessage);
    }

    private String encode(byte[] toEncode) {
        return Base64.encodeToString(toEncode, Base64.NO_WRAP);
    }

    private byte[] decode(String toDecode) {
        return Base64.decode(toDecode, Base64.NO_WRAP);
    }
}
