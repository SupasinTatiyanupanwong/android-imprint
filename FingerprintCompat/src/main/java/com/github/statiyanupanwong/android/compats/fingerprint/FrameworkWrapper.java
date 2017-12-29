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

    @Nullable
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