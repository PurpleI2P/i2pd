package org.purplei2p.i2pd;

public class I2PD_JNI {
    public static native String getABICompiledWith();
	/**
	 * returns 1 if daemon init failed
	 * returns 0 if daemon initialized and started okay
	 */
    public static native int startDaemon();
    //should only be called after startDaemon() success
    public static native void stopDaemon();

    static {
        System.loadLibrary("i2pd");
    }
}
