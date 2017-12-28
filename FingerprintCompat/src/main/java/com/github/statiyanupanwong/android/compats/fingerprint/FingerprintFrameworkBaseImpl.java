package com.github.statiyanupanwong.android.compats.fingerprint;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.support.annotation.Nullable;

class FingerprintFrameworkBaseImpl implements FingerprintFramework.FingerprintFrameworkImpl {
    @Nullable
    @Override
    public FingerprintManager getFingerprintManager(Context context) {
        return null;
    }

    @Override
    public boolean isHardwareDetected(Context context) {
        return false;
    }

    @Override
    public boolean hasEnrolledFingerprints(Context context) {
        return false;
    }

    @Override
    public boolean isFingerprintPermissionGranted(Context context) {
        // Explicitly return true to force hardware availability checking.
        return true;
    }
}
