package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import com.github.statiyanupanwong.android.compats.fingerprint.CryptoAlgorithm;

import javax.crypto.Cipher;

public class DecryptionModeCryptoTask extends FingerprintCryptoTask {
    private final CryptoAlgorithm mMode;
    private final String mAlias;
    private final SecretMessage mSecretMessage;

    public static DecryptionModeCryptoTask with(CryptoAlgorithm mode, String alias, String msg) {
        return new DecryptionModeCryptoTask(mode, alias, msg);
    }

    private DecryptionModeCryptoTask(CryptoAlgorithm mode, String alias, String msg) {
        mMode = mode;
        mAlias = alias;
        mSecretMessage = SecretMessage.fromString(msg);
    }

    @Override
    Cipher getCipher() throws Exception {
        switch (mMode) {
            case AES:
                return new AesCipherProvider(mAlias).getCipherForDecryption(mSecretMessage.getIv());
            case RSA:
                return new RsaCipherProvider(mAlias).getCipherForDecryption();
            default:
                return null;
        }
    }
}
