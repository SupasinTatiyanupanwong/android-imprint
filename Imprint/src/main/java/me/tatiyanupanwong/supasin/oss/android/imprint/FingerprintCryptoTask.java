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

import android.annotation.TargetApi;
import android.hardware.fingerprint.FingerprintManager;
import android.os.AsyncTask;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

@TargetApi(23)
abstract class FingerprintCryptoTask extends AsyncTask<Void, Void, Boolean> {
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private final String mAlias;

    private KeyStore mKeyStore;
    private Cipher mCipher;
    private FingerprintManager.CryptoObject mCryptoObject;
    private Throwable mThrowable;

    FingerprintCryptoTask(String alias) {
        mAlias = alias;
    }

    abstract void initCipher(Cipher cipher, SecretKey secretKey) throws Exception;

    abstract void onCryptoTaskSucceeded(FingerprintManager.CryptoObject cryptoObject);

    abstract void onCryptoTaskFailed(Throwable throwable);

    private void initKeystore() throws Exception {
        mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        mKeyStore.load(null);
    }

    private void initSecretKey() throws Exception {
        if (!mKeyStore.containsAlias(mAlias)) {
            KeyGenerator generator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

            generator.init(new KeyGenParameterSpec.Builder(mAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(true)
                    .build()
            );

            generator.generateKey();
        }
    }

    private void createCipher() throws Exception {
        try {
            mCipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);

            SecretKey secretKey = (SecretKey) mKeyStore.getKey(mAlias, null);

            initCipher(mCipher, secretKey);
        } catch (KeyPermanentlyInvalidatedException e) {
            mKeyStore.deleteEntry(mAlias);
            throw e;
        }
    }

    private void initCryptoObject() {
        mCryptoObject = new FingerprintManager.CryptoObject(mCipher);
    }

    @Override
    protected final Boolean doInBackground(Void... params) {
        try {
            initKeystore();
            initSecretKey();
            createCipher();
            initCryptoObject();
            return true;
        } catch (Exception e) {
            mThrowable = e;
            return false;
        }
    }

    @Override
    protected final void onPostExecute(final Boolean isSuccess) {
        if (isSuccess) {
            onCryptoTaskSucceeded(mCryptoObject);
        } else {
            onCryptoTaskFailed(mThrowable);
        }
    }
}
