package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import android.annotation.TargetApi;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@TargetApi(23)
class AesCipherProvider extends CipherProvider {
    AesCipherProvider(String alias) throws Exception {
        super(alias);
    }

    private SecretKey findOrCreateKey(String alias) throws Exception {
        if (keyExists(alias)) {
            return getKey(alias);
        }
        return createKey(alias);
    }

    private SecretKey getKey(String alias) throws Exception {
        return (SecretKey) mKeyStore.getKey(alias, null);
    }

    private SecretKey createKey(String alias) throws Exception {
        KeyGenerator generator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        generator.init(new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .build()
        );

        return generator.generateKey();
    }

    Cipher getCipherForDecryption(byte[] iv) throws Exception {
        Cipher cipher = createCipher();
        SecretKey key = getKey(mAlias);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher;
    }

    @Override
    Cipher createCipherForEncryption() throws Exception {
        Cipher cipher = createCipher();
        SecretKey key = findOrCreateKey(mAlias);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

    @Override
    Cipher createCipher() throws Exception {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);
    }
}
