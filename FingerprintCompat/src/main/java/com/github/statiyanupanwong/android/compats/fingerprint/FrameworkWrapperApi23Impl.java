package com.github.statiyanupanwong.android.compats.fingerprint;

import android.Manifest;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.support.annotation.Nullable;

/**
 * Explicitly get fingerprint system service, regardless of feature declaration.
 * See: https://issuetracker.google.com/issues/37132365
 */
@TargetApi(23)
@SuppressLint("MissingPermission")
class FrameworkWrapperApi23Impl extends FrameworkWrapperBaseImpl {
    @Nullable
    @Override
    public FingerprintManager getFingerprintManager(Context context) {
        try {
            return (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
        } catch (Exception ignored) {
            return null;
        }
    }

    @Override
    public boolean hasEnrolledFingerprints(Context context) {
        final FingerprintManager fingerprintManager = getFingerprintManager(context);
        if (fingerprintManager == null) {
            return false;
        }
        try {
            return fingerprintManager.hasEnrolledFingerprints();
        } catch (Exception ignored) {
            return false;
        }
    }

    @Override
    public boolean isHardwareDetected(Context context) {
        final FingerprintManager fingerprintManager = getFingerprintManager(context);
        if (fingerprintManager == null) {
            return false;
        }
        try {
            return fingerprintManager.isHardwareDetected();
        } catch (Exception ignored) {
            return false;
        }
    }

    @Override
    public boolean isFingerprintPermissionGranted(Context context) {
        try {
            return context.checkSelfPermission(
                    Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED;
        } catch (Exception ignored) {
            return false;
        }
    }
}
