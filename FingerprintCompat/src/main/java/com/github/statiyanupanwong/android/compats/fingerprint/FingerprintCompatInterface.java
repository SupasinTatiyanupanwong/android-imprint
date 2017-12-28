package com.github.statiyanupanwong.android.compats.fingerprint;

/**
 * Exposing public APIs of {@link FingerprintCompat FingerprintCompat} library.
 */
interface FingerprintCompatInterface {
    void authenticate(FingerprintCompat.AuthenticationCallback callback);
}
