# how to compile?
## Install the gradle + NDK or use android-studio
[https://gradle.org/install/](https://gradle.org/install/)

## Install the depencies
```
git clone https://github.com/PurpleI2P/Boost-for-Android-Prebuilt.git -b boost-1_72_0
git clone https://github.com/PurpleI2P/android-ifaddrs.git
git clone https://github.com/PurpleI2P/OpenSSL-for-Android-Prebuilt.git
git clone https://github.com/PurpleI2P/MiniUPnP-for-Android-Prebuilt.git
```
## Set libs in jni/Application.mk on 24 line:
```
# change to your own
I2PD_LIBS_PATH = /home/user/i2pd/android/
```

## compile apk file
gradle clean assembleRelease
