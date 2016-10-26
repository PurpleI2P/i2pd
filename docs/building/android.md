Building on Android
===================

There are two versions: with QT and without QT.

Pre-requesties
--------------

You need to install Android SDK, NDK  and QT with android support.

- [SDK](https://developer.android.com/studio/index.html) (choose command line tools only)
- [NDK](https://developer.android.com/ndk/downloads/index.html)
- [QT](https://www.qt.io/download-open-source/)(for QT only).
  Choose one for your platform for android. For example QT 5.6 under Linux would be [this file](http://download.qt.io/official_releases/qt/5.6/5.6.1-1/qt-opensource-linux-x64-android-5.6.1-1.run)

You also need Java JDK and Ant.

QT-Creator (for QT only)
------------------------

Open QT-creator that should be installed with QT.
Go to Settings/Anndroid and specify correct paths to SDK and NDK.
If everything is correct you will see two set avaiable:
Android for armeabi-v7a (gcc, qt) and Android for x86 (gcc, qt).

Dependencies
--------------

Take following pre-compiled binaries from PurpleI2P's repositories.

	git clone https://github.com/PurpleI2P/Boost-for-Android-Prebuilt.git
	git clone https://github.com/PurpleI2P/OpenSSL-for-Android-Prebuilt.git
	git clone https://github.com/PurpleI2P/MiniUPnP-for-Android-Prebuilt.git
	git clone https://github.com/PurpleI2P/android-ifaddrs.git

Building the app with QT
------------------------

- Open `qt/i2pd_qt/i2pd_qt.pro` in the QT-creator
- Change line `MAIN_PATH = /path/to/libraries` to an actual path where you put the dependancies to
- Select appropriate project (usually armeabi-v7a) and build
- You will find an .apk file in `android-build/bin` folder

Building the app without QT
---------------------------

- Change line `I2PD_LIBS_PATH` in `android/jni/Application.mk` to an actual path where you put the dependancies to
- Run `ndk-build -j4` from andorid folder
- Create or edit file 'local.properties'. Place 'sdk.dir=<path to SDK>' and 'ndk.dir=<path to NDK>'
- Run `ant clean debug`

Creating release .apk
----------------------

In order to create release .apk you must obtain a Java keystore file(.jks). Either you have in already, or you can generate it yourself using keytool, or from one of you existing well-know ceritificates.
For example, i2pd release are signed with this [certificate](https://github.com/PurpleI2P/i2pd/blob/openssl/contrib/certificates/router/orignal_at_mail.i2p.crt).

Create file 'ant.propeties':

	key.store='path to keystore file'
	key.alias='alias name'
	key.store.password='keystore password'
	key.alias.password='alias password'

Run `ant clean release`
