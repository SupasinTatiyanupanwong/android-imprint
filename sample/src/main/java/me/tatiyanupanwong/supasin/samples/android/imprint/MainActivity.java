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

package me.tatiyanupanwong.supasin.samples.android.imprint;

import android.app.Activity;
import android.os.Bundle;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import me.tatiyanupanwong.supasin.android.imprint.Imprint;
import me.tatiyanupanwong.supasin.android.imprint.domain.DecryptionResponse;
import me.tatiyanupanwong.supasin.android.imprint.domain.EncryptionResponse;
import me.tatiyanupanwong.supasin.android.imprint.domain.FingerprintResult;

public class MainActivity extends AppCompatActivity implements View.OnClickListener,
        Imprint.EncryptionCallback, Imprint.DecryptionCallback {
    private ViewHolder mViews;
    private Imprint mImprint;

    private String mInitialText;
    private String mEncrypted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mViews = new ViewHolder(this);
        mImprint = Imprint.from(this);

        mInitialText = "Test";

        mViews.button.setOnClickListener(this);
    }

    @Override
    public void onClick(View view) {
        if (view == mViews.button) {
            if (mImprint.isAvailable()) {
                mViews.button.setEnabled(false);
                mViews.textView.setText(R.string.touch_sensor);
                if (mEncrypted == null) {
                    mImprint.encrypt(mInitialText, this);
                } else {
                    mImprint.decrypt(mEncrypted, this);
                }
            } else {
                mViews.textView.setText(R.string.operation_not_available);
            }
        }
    }

    @Override
    protected void onPause() {
        mImprint.cancel();
        mViews.textView.setText(R.string.operation_canceled);
        super.onPause();
    }

    @Override
    public void onEncryptionResponse(@NonNull EncryptionResponse response) {
        if (response.getResult() == FingerprintResult.AUTHENTICATED) {
            mEncrypted = response.getEncrypted();
            String str = "{"
                    + mInitialText
                    + " -> "
                    + mEncrypted
                    + "}";
            mViews.textView.setText(str);
            mViews.button.setEnabled(true);
        } else {
            mViews.textView.setText(response.getMessage());
        }
    }

    @Override
    public void onEncryptionFailure(@NonNull Throwable throwable) {
        mViews.textView.setText(TextUtils.isEmpty(throwable.getMessage())
                ? getString(R.string.encryption_failed)
                : throwable.getMessage());
        mViews.button.setEnabled(true);
        throwable.printStackTrace();
    }

    @Override
    public void onDecryptionResponse(@NonNull DecryptionResponse response) {
        if (response.getResult() == FingerprintResult.AUTHENTICATED) {
            String str = "{"
                    + mEncrypted
                    + " -> "
                    + response.getDecrypted()
                    + "}";
            mViews.textView.setText(str);
            mViews.button.setEnabled(true);
        } else {
            mViews.textView.setText(response.getMessage());
        }
    }

    @Override
    public void onDecryptionFailure(@NonNull Throwable throwable) {
        if (throwable instanceof KeyPermanentlyInvalidatedException) {
            mEncrypted = null;
            mViews.textView.setText(R.string.key_permanently_invalidated);
        } else {
            mViews.textView.setText(TextUtils.isEmpty(throwable.getMessage())
                    ? getString(R.string.decryption_failed)
                    : throwable.getMessage());
        }
        mViews.button.setEnabled(true);
        throwable.printStackTrace();
    }

    private static final class ViewHolder {
        Button button;
        TextView textView;

        ViewHolder(Activity activity) {
            button = activity.findViewById(R.id.touch_me);
            textView = activity.findViewById(R.id.status);
        }
    }
}
