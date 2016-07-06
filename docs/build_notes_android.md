Pre-requesties
--------------

You need to install Android SDK, NDK  and QT with android support.

SDK (choose command line tools only)  
https://developer.android.com/studio/index.html  
NDK 
https://developer.android.com/ndk/downloads/index.html

QT
https://www.qt.io/download-open-source/
Choose one for your platform for android
For example QT 5.6 under Linux would be
http://download.qt.io/official_releases/qt/5.6/5.6.1-1/qt-opensource-linux-x64-android-5.6.1-1.run  

You also need Java JDK and Ant.

QT-Creator
----------
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


Building the app
----------------
Open qt/i2pd_qt/i2pd_qt.pro in the QT-creator.
Change line MAIN_PATH = /path/to/libraries to actual path where did you put the dependancies to.
Select appropriate project (usually armeabi-v7a) and build.
You will find an .apk file in android-build/bin folder.  


