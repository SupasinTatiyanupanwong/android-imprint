package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import android.annotation.TargetApi;
import android.security.keystore.KeyPermanentlyInvalidatedException;

import java.security.KeyStore;
import java.util.Enumeration;

import javax.crypto.Cipher;

@TargetApi(23)
abstract class CipherProvider {
    static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    final String mAlias;
    final KeyStore mKeyStore;

    CipherProvider(String alias) throws Exception {
        mAlias = alias;
        mKeyStore = getKeystore();
    }

    abstract Cipher createCipherForEncryption() throws Exception;

    abstract Cipher createCipher() throws Exception;

    Cipher getCipherForEncryption() throws Exception {
        try {
            return createCipherForEncryption();
        } catch (KeyPermanentlyInvalidatedException e) {
            removeKey(mAlias);
            return createCipherForEncryption();
        }
    }

    private KeyStore getKeystore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        return keyStore;
    }

    private void removeKey(String alias) throws Exception {
        if (keyExists(alias)) {
            KeyStore keyStore = getKeystore();
            keyStore.deleteEntry(alias);
        }
    }

    boolean keyExists(String alias) throws Exception {
        KeyStore keyStore = getKeystore();
        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            if (alias.equals(aliases.nextElement())) {
                return true;
            }
        }

        return false;
    }
}
