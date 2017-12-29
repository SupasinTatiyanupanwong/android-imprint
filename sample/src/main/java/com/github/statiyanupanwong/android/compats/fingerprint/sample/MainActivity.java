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

package com.github.statiyanupanwong.android.compats.fingerprint.sample;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintCompat;
import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintResponse;

public class MainActivity extends AppCompatActivity implements View.OnClickListener,
        FingerprintCompat.EncryptionCallback, FingerprintCompat.DecryptionCallback {

    private Button mButton;
    private String mEncrypted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mButton = findViewById(R.id.helloWorld);
        mButton.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if (mButton.equals(v)) {
            if (mEncrypted == null) {
                FingerprintCompat.of(this).encrypt("Test", this);
            } else {
                FingerprintCompat.of(this).decrypt(mEncrypted, this);
            }
        }
    }

    @Override
    public void onEncryptionResponse(FingerprintResponse response) {
        if (response.isSuccessful()) {
            mEncrypted = response.getData();
        }
    }

    @Override
    public void onEncryptionFailure(Throwable throwable) {
        throwable.printStackTrace();
    }

    @Override
    public void onDecryptionResponse(FingerprintResponse response) {
        if (response.isSuccessful()) {
            Toast.makeText(getApplicationContext(), response.getData(), Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onDecryptionFailure(Throwable throwable) {
        throwable.printStackTrace();
    }
}
