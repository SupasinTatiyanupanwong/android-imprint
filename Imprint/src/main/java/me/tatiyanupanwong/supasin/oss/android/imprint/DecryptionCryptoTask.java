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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import me.tatiyanupanwong.supasin.oss.android.imprint.exception.CryptoDataException;

final class DecryptionCryptoTask extends FingerprintCryptoTask {
    private final CryptoData mCryptoData;

    private DecryptionCryptoTask(String alias, String cryptoDataString,
            Callback callback) throws CryptoDataException {
        super(alias, callback);
        mCryptoData = CryptoData.fromString(cryptoDataString);
    }

    static DecryptionCryptoTask with(String alias, String cryptoDataString,
            Callback callback) throws CryptoDataException {
        return new DecryptionCryptoTask(alias, cryptoDataString, callback);
    }

    @Override
    void initCipher(Cipher cipher, SecretKey secretKey) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(mCryptoData.getIv()));
    }
}
