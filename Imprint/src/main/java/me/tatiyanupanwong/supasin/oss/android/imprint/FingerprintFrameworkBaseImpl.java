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
