package com.github.statiyanupanwong.android.compats.fingerprint;

import android.Manifest;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.support.annotation.Nullable;

@TargetApi(23)
@SuppressLint("MissingPermission")
class FingerprintFrameworkApi23Impl extends FingerprintFrameworkBaseImpl {
    @Nullable
    @Override
    public FingerprintManager getFingerprintManager(Context context) {
        if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            return (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
        } else {
            return null;
        }
    }

    @Override
    public boolean hasEnrolledFingerprints(Context context) {
        final FingerprintManager fingerprintManager = getFingerprintManager(context);
        return (fingerprintManager != null) && fingerprintManager.hasEnrolledFingerprints();
    }

    @Override
    public boolean isHardwareDetected(Context context) {
        final FingerprintManager fingerprintManager = getFingerprintManager(context);
        return (fingerprintManager != null) && fingerprintManager.isHardwareDetected();
    }

    @Override
    public boolean isFingerprintPermissionGranted(Context context) {
        return context.checkSelfPermission(
                Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED;
    }
}
