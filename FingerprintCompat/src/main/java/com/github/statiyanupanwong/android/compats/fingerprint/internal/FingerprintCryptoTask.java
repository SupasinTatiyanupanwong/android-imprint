package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import android.annotation.TargetApi;
import android.os.AsyncTask;

import com.github.statiyanupanwong.android.compats.fingerprint.CryptoAlgorithm;

import javax.crypto.Cipher;

@TargetApi(23)
abstract class FingerprintCryptoTask {

    abstract Cipher getCipher(CryptoAlgorithm algorithm, String alias) throws Exception;

    public final void execute() {
        new CryptoTask().execute((Void) null);
    }

    private class CryptoTask extends AsyncTask<Void, Void, Boolean> {
        @Override
        protected Boolean doInBackground(Void... voids) {
            return null;
        }
    }
}
