package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import android.annotation.TargetApi;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

@TargetApi(23)
class RsaCipherProvider extends CipherProvider {
    RsaCipherProvider(String alias) throws Exception {
        super(alias);
    }

    private PrivateKey getPrivateKey(KeyStore keyStore, String alias) throws Exception {
        return (PrivateKey) keyStore.getKey(alias, null);
    }

    private PublicKey getPublicKey(KeyFactory keyFactory, KeyStore keyStore) throws Exception {
        PublicKey publicKey = keyStore.getCertificate(mAlias).getPublicKey();
        KeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
        return keyFactory.generatePublic(spec);
    }

    Cipher getCipherForDecryption() throws Exception {
        Cipher cipher = createCipher();
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(mKeyStore, mAlias));
        return cipher;
    }

    @Override
    Cipher createCipherForEncryption() throws Exception {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);

        generator.initialize(new KeyGenParameterSpec.Builder(mAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setUserAuthenticationRequired(true)
                .build()
        );

        generator.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
        Cipher cipher = createCipher();
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(keyFactory, mKeyStore));

        return cipher;
    }

    @Override
    Cipher createCipher() throws Exception {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA + "/"
                + KeyProperties.BLOCK_MODE_ECB + "/"
                + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
    }
}
