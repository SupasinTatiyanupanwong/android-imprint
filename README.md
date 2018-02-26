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
implementation 'com.github.SupasinTatiyanupanwong:android-imprint:1.0.0-beta2'
```

Usage
--------
1. Add `android.permission.USE_FINGERPRINT` in AndroidManifest
```xml
<uses-permission android:name="android.permission.USE_FINGERPRINT"/>
```

2. Instantiate an instance of `Imprint`
```java
private Imprint mImprint;
mImprint = Imprint.of((Context) this);
```

3. Call `Imprint` APIs to interact with fingerprint services

3.1 You can safe guard the operation by using `Imprint#isAvailable()`

3.2 `Imprint` allows you to authenticate your user, encrypt or decrypt your user data as follows

```java
mImprint.authenticate((AuthenticationCallback) this);
mImprint.encrypt((String) toEncrypt, (EncryptionCallback) this);
mImprint.decrypt((String) toDecrypt, (DecryptionCallback) this);
```

3.3 To cancel the operation, simply call `Imprint#cancel()`. Note that this must be called before `Activity#onPause()`

License
=======

```
Copyright (C) 2017-2018 Supasin Tatiyanupanwong

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
