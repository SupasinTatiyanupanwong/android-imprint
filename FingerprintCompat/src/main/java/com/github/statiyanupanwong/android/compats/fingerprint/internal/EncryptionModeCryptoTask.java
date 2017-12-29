package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import com.github.statiyanupanwong.android.compats.fingerprint.CryptoAlgorithm;

import javax.crypto.Cipher;

public class EncryptionModeCryptoTask extends FingerprintCryptoTask {
    private final CryptoAlgorithm mMode;
    private final String mAlias;

    public static EncryptionModeCryptoTask with(CryptoAlgorithm mode, String alias) {
        return new EncryptionModeCryptoTask(mode, alias);
    }

    private EncryptionModeCryptoTask(CryptoAlgorithm mode, String alias) {
        mMode = mode;
        mAlias = alias;
    }

    @Override
    Cipher getCipher() throws Exception {
        switch (mMode) {
            case AES:
                return new AesCipherProvider(mAlias).getCipherForEncryption();
            case RSA:
                return new RsaCipherProvider(mAlias).getCipherForEncryption();
            default:
                return null;
        }
    }
}
