package com.github.statiyanupanwong.android.compats.fingerprint.internal;

import android.annotation.TargetApi;
import android.hardware.fingerprint.FingerprintManager;
import android.os.AsyncTask;

import javax.crypto.Cipher;

@TargetApi(23)
abstract class FingerprintCryptoTask {
    private Cipher mCipher;
    private Throwable mThrowable;

    abstract Cipher getCipher() throws Exception;

    public final void execute(Callback callback) {
        new CryptoTask(callback).execute((Void) null);
    }

    public interface Callback {
        void onCryptoTaskSucceeded(FingerprintManager.CryptoObject crypto);

        void onCryptoTaskFailed(Throwable throwable);
    }

    private class CryptoTask extends AsyncTask<Void, Void, Boolean> {
        final Callback mCallback;

        CryptoTask(Callback callback) {
            mCallback = callback;
        }

        private FingerprintManager.CryptoObject getCryptoObject(Cipher cipher) {
            return new FingerprintManager.CryptoObject(cipher);
        }

        @Override
        protected Boolean doInBackground(Void... voids) {
            try {
                mCipher = getCipher();
                return true;
            } catch (Exception e) {
                mThrowable = e;
                return false;
            }
        }

        @Override
        protected final void onPostExecute(final Boolean isSuccess) {
            if (isSuccess) {
                mCallback.onCryptoTaskSucceeded(getCryptoObject(mCipher));
            } else {
                mCallback.onCryptoTaskFailed(mThrowable);
            }
        }
    }
}
