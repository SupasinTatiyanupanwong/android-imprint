package com.github.statiyanupanwong.android.compats.fingerprint;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.support.annotation.Nullable;

class FrameworkWrapper {
    private static final FrameworkWrapperImpl IMPL;
    private final Context mContext;

    static {
        if (Build.VERSION.SDK_INT >= 23) {
            IMPL = new FrameworkWrapperApi23Impl();
        } else {
            IMPL = new FrameworkWrapperBaseImpl();
        }
    }

    FrameworkWrapper(Context context) {
        mContext = context;
    }

    FingerprintManager getFingerprintManager() {
        return IMPL.getFingerprintManager(mContext);
    }

    boolean isHardwareDetected() {
        return IMPL.isHardwareDetected(mContext);
    }

    boolean hasEnrolledFingerprints() {
        return IMPL.hasEnrolledFingerprints(mContext);
    }

    boolean isFingerprintPermissionGranted() {
        return IMPL.isFingerprintPermissionGranted(mContext);
    }

    interface FrameworkWrapperImpl {
        @Nullable
        FingerprintManager getFingerprintManager(Context context);

        boolean isHardwareDetected(Context context);

        boolean hasEnrolledFingerprints(Context context);

        boolean isFingerprintPermissionGranted(Context context);
    }
}
