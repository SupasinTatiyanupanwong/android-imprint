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

package me.tatiyanupanwong.supasin.oss.samples.android.imprint;

import android.os.Bundle;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import me.tatiyanupanwong.supasin.oss.android.imprint.Imprint;
import me.tatiyanupanwong.supasin.oss.android.imprint.domain.DecryptionResponse;
import me.tatiyanupanwong.supasin.oss.android.imprint.domain.EncryptionResponse;
import me.tatiyanupanwong.supasin.oss.android.imprint.domain.FingerprintResult;

public class MainActivity extends AppCompatActivity
        implements View.OnClickListener, Imprint.EncryptionCallback, Imprint.DecryptionCallback {

    private Button mButton;
    private TextView mTextView;

    private Imprint mImprint;

    private String mInitialText;
    private String mEncrypted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mInitialText = "Test";

        mButton = findViewById(R.id.touch_me);
        mTextView = findViewById(R.id.status);
        mButton.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if (mButton.equals(v)) {
            mImprint = Imprint.of(this);
            if (mImprint.isAvailable()) {
                mButton.setEnabled(false);
                mTextView.setText(R.string.touch_sensor);
                if (mEncrypted == null) {
                    mImprint.encrypt(mInitialText, this);
                } else {
                    mImprint.decrypt(mEncrypted, this);
                }
            } else {
                mTextView.setText(R.string.operation_not_available);
            }
        }
    }

    @Override
    protected void onPause() {
        if (mImprint != null) {
            mImprint.cancel();
            mImprint = null;
            mTextView.setText(R.string.operation_canceled);
        }
        super.onPause();
    }

    @Override
    public void onEncryptionResponse(@NonNull EncryptionResponse response) {
        if (response.getResult() == FingerprintResult.AUTHENTICATED) {
            mImprint = null;
            mEncrypted = response.getEncrypted();
            String str = "{"
                    + mInitialText
                    + " -> "
                    + mEncrypted
                    + "}";
            mTextView.setText(str);
            mButton.setEnabled(true);
        } else {
            mTextView.setText(response.getMessage());
        }
    }

    @Override
    public void onEncryptionFailure(@NonNull Throwable throwable) {
        mImprint = null;
        mTextView.setText(TextUtils.isEmpty(throwable.getMessage())
                ? getString(R.string.encryption_failed)
                : throwable.getMessage());
        mButton.setEnabled(true);
        throwable.printStackTrace();
    }

    @Override
    public void onDecryptionResponse(@NonNull DecryptionResponse response) {
        if (response.getResult() == FingerprintResult.AUTHENTICATED) {
            mImprint = null;
            String str = "{"
                    + mEncrypted
                    + " -> "
                    + response.getDecrypted()
                    + "}";
            mTextView.setText(str);
            mButton.setEnabled(true);
        } else {
            mTextView.setText(response.getMessage());
        }
    }

    @Override
    public void onDecryptionFailure(@NonNull Throwable throwable) {
        mImprint = null;
        if (throwable instanceof KeyPermanentlyInvalidatedException) {
            mEncrypted = null;
            mTextView.setText(R.string.key_permanently_invalidated);
        } else {
            mTextView.setText(TextUtils.isEmpty(throwable.getMessage())
                    ? getString(R.string.decryption_failed)
                    : throwable.getMessage());
        }
        mButton.setEnabled(true);
        throwable.printStackTrace();
    }
}
