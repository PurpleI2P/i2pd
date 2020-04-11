#include <jni.h>
#include "org_purplei2p_i2pd_I2PD_JNI.h"
#include "DaemonAndroid.h"
#include "RouterContext.h"
#include "ClientContext.h"
#include "Transports.h"

JNIEXPORT jstring JNICALL Java_org_purplei2p_i2pd_I2PD_1JNI_getABICompiledWith
	(JNIEnv *env, jclass clazz) {
#if defined(__arm__)
	#if defined(__ARM_ARCH_7A__)
		#if defined(__ARM_NEON__)
			#if defined(__ARM_PCS_VFP)
				#define ABI "armeabi-v7a/NEON (hard-float)"
				#else
				#define ABI "armeabi-v7a/NEON"
			#endif
			#else
			#if defined(__ARM_PCS_VFP)
				#define ABI "armeabi-v7a (hard-float)"
				#else
				#define ABI "armeabi-v7a"
			#endif
		#endif
		#else
		#define ABI "armeabi"
	#endif
	#elif defined(__i386__)
	#define ABI "x86"
	#elif defined(__x86_64__)
	#define ABI "x86_64"
	#elif defined(__mips64)  /* mips64el-* toolchain defines __mips__ too */
	#define ABI "mips64"
	#elif defined(__mips__)
	#define ABI "mips"
	#elif defined(__aarch64__)
	#define ABI "arm64-v8a"
	#else
	#define ABI "unknown"
#endif

	return env->NewStringUTF(ABI);
}

JNIEXPORT jstring JNICALL Java_org_purplei2p_i2pd_I2PD_1JNI_startDaemon
	(JNIEnv *env, jclass clazz) {
	return env->NewStringUTF(i2p::android::start().c_str());
}

JNIEXPORT void JNICALL Java_org_purplei2p_i2pd_I2PD_1JNI_stopDaemon
	(JNIEnv *env, jclass clazz) {
	i2p::android::stop();
}

JNIEXPORT void JNICALL Java_org_purplei2p_i2pd_I2PD_1JNI_stopAcceptingTunnels
	(JNIEnv *env, jclass clazz) {
	i2p::context.SetAcceptsTunnels (false);
}

JNIEXPORT void JNICALL Java_org_purplei2p_i2pd_I2PD_1JNI_startAcceptingTunnels
	(JNIEnv *env, jclass clazz) {
	i2p::context.SetAcceptsTunnels (true);
}

JNIEXPORT void JNICALL Java_org_purplei2p_i2pd_I2PD_1JNI_reloadTunnelsConfigs
	(JNIEnv *env, jclass clazz) {
	i2p::client::context.ReloadConfig();
}

JNIEXPORT void JNICALL Java_org_purplei2p_i2pd_I2PD_1JNI_onNetworkStateChanged
	(JNIEnv *env, jclass clazz, jboolean isConnected) {
	bool isConnectedBool = (bool) isConnected;
	i2p::transport::transports.SetOnline (isConnectedBool);
}

JNIEXPORT void JNICALL Java_org_purplei2p_i2pd_I2PD_1JNI_setDataDir
	(JNIEnv *env, jclass clazz, jstring jdataDir) {

	/*
	// Method 1: convert UTF-16 jstring to std::string (https://stackoverflow.com/a/41820336)
	const jclass stringClass = env->GetObjectClass(jdataDir);
	const jmethodID getBytes = env->GetMethodID(stringClass, "getBytes", "(Ljava/lang/String;)[B");
	const jbyteArray stringJbytes = (jbyteArray) env->CallObjectMethod(jdataDir, getBytes, env->NewStringUTF("UTF-8"));

	size_t length = (size_t) env->GetArrayLength(stringJbytes);
	jbyte* pBytes = env->GetByteArrayElements(stringJbytes, NULL);

	std::string dataDir = std::string((char *)pBytes, length);
	env->ReleaseByteArrayElements(stringJbytes, pBytes, JNI_ABORT);

	env->DeleteLocalRef(stringJbytes);
	env->DeleteLocalRef(stringClass); */

	// Method 2: get string chars and make char array.
	auto dataDir = env->GetStringUTFChars(jdataDir, NULL);
	env->ReleaseStringUTFChars(jdataDir, dataDir);

	// Set DataDir
	i2p::android::SetDataDir(dataDir);
}
