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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

final class DecryptionCipherTask extends FingerprintCipherTask {
    private final String mToDecrypt;

    private DecryptionCipherTask(String alias, String toDecrypt, Callback callback) {
        super(alias, callback);
        mToDecrypt = toDecrypt;
    }

    static DecryptionCipherTask with(String alias, String toDecrypt, Callback callback) {
        return new DecryptionCipherTask(alias, toDecrypt, callback);
    }

    @Override
    void initCipher(Cipher cipher, SecretKey secretKey) throws Exception {
        CryptoData cryptoData = CryptoData.fromString(mToDecrypt);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(cryptoData.getIv()));
    }
}
