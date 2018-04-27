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

import android.text.TextUtils;
import android.util.Base64;

/**
 * @author Supasin Tatiyanupanwong
 */
final class CryptoData {
    private static final String SEPARATOR = "::";

    private final String mEncodedIv;
    private final String mEncodedMessage;

    private CryptoData(byte[] ivBytes, byte[] messageBytes) {
        mEncodedIv = encode(ivBytes);
        mEncodedMessage = encode(messageBytes);
    }

    private CryptoData(String iv, String message) {
        mEncodedIv = iv;
        mEncodedMessage = message;
    }

    static CryptoData fromBytes(byte[] ivBytes, byte[] messageBytes) {
        return new CryptoData(ivBytes, messageBytes);
    }

    static CryptoData fromString(String input) throws Imprint.CryptoDataException {
        verifyCryptoDataString(input);

        String[] inputParams = input.split(SEPARATOR);
        return new CryptoData(inputParams[0], inputParams[1]);
    }

    static void verifyCryptoDataString(String input) throws Imprint.CryptoDataException {
        if (TextUtils.isEmpty(input) || !input.contains(SEPARATOR)) {
            throw new Imprint.CryptoDataException();
        }
    }

    @Override
    public String toString() {
        return mEncodedIv + SEPARATOR + mEncodedMessage;
    }

    byte[] getIv() {
        return decode(mEncodedIv);
    }

    byte[] getMessage() {
        return decode(mEncodedMessage);
    }

    private String encode(byte[] toEncode) {
        return Base64.encodeToString(toEncode, Base64.NO_WRAP);
    }

    private byte[] decode(String toDecode) {
        return Base64.decode(toDecode, Base64.NO_WRAP);
    }
}
