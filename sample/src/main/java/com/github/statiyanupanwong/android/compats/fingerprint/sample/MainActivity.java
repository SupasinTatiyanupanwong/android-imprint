package com.github.statiyanupanwong.android.compats.fingerprint.sample;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;

import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintCompat;
import com.github.statiyanupanwong.android.compats.fingerprint.FingerprintResponse;

public class MainActivity extends AppCompatActivity implements View.OnClickListener,
        FingerprintCompat.AuthenticationCallback {

    private Button mButton;

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
            FingerprintCompat.with(this).authenticate(this);
        }
    }

    @Override
    public void onAuthenticationResponse(FingerprintResponse response) {

    }

    @Override
    public void onAuthenticationFailure(Throwable throwable) {

    }
}
