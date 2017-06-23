package org.purplei2p.i2pd;

import java.util.HashSet;
import java.util.Set;

import android.util.Log;

public class DaemonSingleton {
	private static final String TAG="i2pd";
	private static final DaemonSingleton instance = new DaemonSingleton();
	public static interface StateUpdateListener { void daemonStateUpdate(); }
	private final Set<StateUpdateListener> stateUpdateListeners = new HashSet<StateUpdateListener>();

	public static DaemonSingleton getInstance() {
		return instance;
	}
	
	public synchronized void addStateChangeListener(StateUpdateListener listener) { stateUpdateListeners.add(listener); }
	public synchronized void removeStateChangeListener(StateUpdateListener listener) { stateUpdateListeners.remove(listener); }
	
	public synchronized void stopAcceptingTunnels() {
		if(isStartedOkay()){
			state=State.gracefulShutdownInProgress;
			fireStateUpdate();
			I2PD_JNI.stopAcceptingTunnels();
		}
	}
	
	public void onNetworkStateChange(boolean isConnected) {
		I2PD_JNI.onNetworkStateChanged(isConnected);
	}
	
	private boolean startedOkay;

	public static enum State {uninitialized,starting,jniLibraryLoaded,startedOkay,startFailed,gracefulShutdownInProgress};
	
	private State state = State.uninitialized;
	
	public State getState() { return state; }
	
	public synchronized void start() {
		if(state != State.uninitialized)return;
		state = State.starting;
		fireStateUpdate();
		new Thread(new Runnable(){

			@Override
			public void run() {
				try {
					I2PD_JNI.loadLibraries();
					synchronized (DaemonSingleton.this) {
						state = State.jniLibraryLoaded;
						fireStateUpdate();
					}
				} catch (Throwable tr) {
					lastThrowable=tr;
					synchronized (DaemonSingleton.this) {
						state = State.startFailed;
						fireStateUpdate();
					}
					return;
				}
				try {
					synchronized (DaemonSingleton.this) {
						daemonStartResult = I2PD_JNI.startDaemon();
						if("ok".equals(daemonStartResult)){
							state=State.startedOkay;
							setStartedOkay(true);
						}else state=State.startFailed;
						fireStateUpdate();
					}
				} catch (Throwable tr) {
					lastThrowable=tr;
					synchronized (DaemonSingleton.this) {
						state = State.startFailed;
						fireStateUpdate();
					}
					return;
				}				
			}
			
		}, "i2pdDaemonStart").start();
	}
	private Throwable lastThrowable;
	private String daemonStartResult="N/A";

	private synchronized void fireStateUpdate() {
		Log.i(TAG, "daemon state change: "+state);
		for(StateUpdateListener listener : stateUpdateListeners) {
			try { 
				listener.daemonStateUpdate(); 
			} catch (Throwable tr) { 
				Log.e(TAG, "exception in listener ignored", tr); 
			}
		}
	}

	public Throwable getLastThrowable() {
		return lastThrowable;
	}

	public String getDaemonStartResult() {
		return daemonStartResult;
	}
	
	private final Object startedOkayLock = new Object();

	public boolean isStartedOkay() {
		synchronized (startedOkayLock) {
			return startedOkay;
		}
	}

	private void setStartedOkay(boolean startedOkay) {
		synchronized (startedOkayLock) {
			this.startedOkay = startedOkay;
		}
	}

	public synchronized void stopDaemon() {
		if(isStartedOkay()){
			try {I2PD_JNI.stopDaemon();}catch(Throwable tr){Log.e(TAG, "", tr);}
			setStartedOkay(false);
		}
	}
}
