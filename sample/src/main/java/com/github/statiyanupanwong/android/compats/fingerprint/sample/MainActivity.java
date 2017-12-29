package com.github.statiyanupanwong.android.compats.fingerprint.sample;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;

import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintCompat;
import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintResponse;

public class MainActivity extends AppCompatActivity implements View.OnClickListener,
        FingerprintCompat.EncryptionCallback, FingerprintCompat.DecryptionCallback {

    private Button mButton;
    private String mInitialText = "test";
    private String mEncrypted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mInitialText = "test";

        mButton = findViewById(R.id.helloWorld);
        mButton.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if (mButton.equals(v)) {
            if (mEncrypted == null) {
                FingerprintCompat.of(this).encrypt(mInitialText, this);
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
            String decrypted = response.getData();
        }
    }

    @Override
    public void onDecryptionFailure(Throwable throwable) {
        throwable.printStackTrace();
    }
}
