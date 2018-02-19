Android Imprint Library
========
A wrapper library to simplify fingerprint authentication on Android with a backward compatibility prior to Android M.

Download
--------
Grab it via Gradle:

**Step 1:** Add the JitPack repository to your build file
```groovy
repositories {
    maven { url 'https://jitpack.io' }
}
```
**Step 2:** Add the dependency
```groovy
compile 'com.github.SupasinTatiyanupanwong:android-imprint:1.0.0'
```

Usage
--------
1. Add android.permission.USE_FINGERPRINT in AndroidManifest
```xml
<uses-permission android:name="android.permission.USE_FINGERPRINT"/>
```

2. Call Imprint APIs

The following are Imprint APIs to interact with fingerprint service
```java
Imprint.of((Context) this).authenticate((AuthenticationCallback) this);
Imprint.of((Context) this).encrypt((String) toEncrypt, (EncryptionCallback) this);
Imprint.of((Context) this).decrypt((String) toDecrypt, (DecryptionCallback) this);
```

To check availability of fingerprint authentication, safe guard by

```java
if (Imprint.of((Context) this).isAvailable()) {
    // Can use Imprint APIs here...
} else {
    // Provides fallback here...
}
```

or explicitly handle from callback, for instance,

```java
@Override
public void onAuthenticationFailed(Throwable throwable) {
    if (throwable instanceof FingerprintUnavailableException) {
        // Provides fallback here...
    }
}
```

3. Get response from callback

For Encryption:

```java
@Override
public void onEncryptionResponse(FingerprintResponse response) {
    if (response.isSuccessful()) {
        String encrypted = response.getData(); // This is an input to be given on decryption process.
    }
}
```

For Decryption:

```java
@Override
public void onDecryptionResponse(FingerprintResponse response) {
    if (response.isSuccessful()) {
        String decrypted = response.getData(); // This is an input given on encryption process.
    }
}
```

License
=======

```
Copyright (C) 2017 Supasin Tatiyanupanwong

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
