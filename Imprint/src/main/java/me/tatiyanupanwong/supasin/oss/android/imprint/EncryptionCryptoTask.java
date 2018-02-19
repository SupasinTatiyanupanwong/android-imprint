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

package me.tatiyanupanwong.supasin.oss.android.imprint;

import android.hardware.fingerprint.FingerprintManager;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

final class EncryptionCryptoTask extends FingerprintCryptoTask {
    private final EncryptionTaskCallback mCallback;

    public static EncryptionCryptoTask with(String alias, EncryptionTaskCallback callback) {
        return new EncryptionCryptoTask(alias, callback);
    }

    private EncryptionCryptoTask(String alias, EncryptionTaskCallback callback) {
        super(alias);
        mCallback = callback;
    }

    @Override
    void initCipher(Cipher cipher, SecretKey secretKey) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }

    @Override
    void onCryptoTaskSucceeded(FingerprintManager.CryptoObject cryptoObject) {
        mCallback.onEncryptionTaskSucceeded(cryptoObject);
    }

    @Override
    void onCryptoTaskFailed(Throwable throwable) {
        mCallback.onEncryptionTaskFailed(throwable);
    }

    public interface EncryptionTaskCallback {
        void onEncryptionTaskSucceeded(FingerprintManager.CryptoObject cryptoObject);

        void onEncryptionTaskFailed(Throwable throwable);
    }
}
