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

package me.tatiyanupanwong.supasin.oss.android.imprint;

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
class FingerprintFrameworkApi23Impl extends FingerprintFrameworkBaseImpl {
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
