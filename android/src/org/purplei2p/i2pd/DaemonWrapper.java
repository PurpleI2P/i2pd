package org.purplei2p.i2pd;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;

import android.annotation.TargetApi;
import android.content.res.AssetManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Environment;
import android.util.Log;

import androidx.annotation.RequiresApi;

public class DaemonWrapper {
	private static final String TAG = "i2pd";
	private final AssetManager assetManager;
	private final ConnectivityManager connectivityManager;
	private String i2pdpath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/i2pd/";
	private boolean assetsCopied;

	public interface StateUpdateListener {
		void daemonStateUpdate(State oldValue, State newValue);
	}

	private final Set<StateUpdateListener> stateUpdateListeners = new HashSet<>();

	public synchronized void addStateChangeListener(StateUpdateListener listener) {
		stateUpdateListeners.add(listener);
	}

	public synchronized void removeStateChangeListener(StateUpdateListener listener) {
		stateUpdateListeners.remove(listener);
	}

	private synchronized void setState(State newState) {
		if (newState == null)
			throw new NullPointerException();

		State oldState = state;

		if (oldState == null)
			throw new NullPointerException();

		if (oldState.equals(newState))
			return;

		state = newState;
		fireStateUpdate1(oldState, newState);
	}

	public synchronized void stopAcceptingTunnels() {
		if (isStartedOkay()) {
			setState(State.gracefulShutdownInProgress);
			I2PD_JNI.stopAcceptingTunnels();
		}
	}

	public synchronized void startAcceptingTunnels() {
		if (isStartedOkay()) {
			setState(State.startedOkay);
			I2PD_JNI.startAcceptingTunnels();
		}
	}

	public synchronized void reloadTunnelsConfigs() {
		if (isStartedOkay()) {
			I2PD_JNI.reloadTunnelsConfigs();
		}
	}

	public int getTransitTunnelsCount() {
		return I2PD_JNI.GetTransitTunnelsCount();
	}

	public enum State {
		uninitialized(R.string.uninitialized),
		starting(R.string.starting),
		jniLibraryLoaded(R.string.jniLibraryLoaded),
		startedOkay(R.string.startedOkay),
		startFailed(R.string.startFailed),
		gracefulShutdownInProgress(R.string.gracefulShutdownInProgress),
		stopped(R.string.stopped);

		State(int statusStringResourceId) {
			this.statusStringResourceId = statusStringResourceId;
		}

		private final int statusStringResourceId;

		public int getStatusStringResourceId() {
			return statusStringResourceId;
		}

		public boolean isStartedOkay() {
			return equals(State.startedOkay) || equals(State.gracefulShutdownInProgress);
		}
	}

	private volatile State state = State.uninitialized;

	public State getState() {
		return state;
	}

	public DaemonWrapper(AssetManager assetManager, ConnectivityManager connectivityManager){
		this.assetManager = assetManager;
		this.connectivityManager = connectivityManager;
		setState(State.starting);
		new Thread(() -> {
			try {
				processAssets();
				I2PD_JNI.loadLibraries();
				setState(State.jniLibraryLoaded);
				registerNetworkCallback();
			} catch (Throwable tr) {
				lastThrowable = tr;
				setState(State.startFailed);
				return;
			}
			try {
				synchronized (DaemonWrapper.this) {
					I2PD_JNI.setDataDir(Environment.getExternalStorageDirectory().getAbsolutePath() + "/i2pd");
					daemonStartResult = I2PD_JNI.startDaemon();
					if ("ok".equals(daemonStartResult)) {
						setState(State.startedOkay);
					} else
						setState(State.startFailed);
				}
			} catch (Throwable tr) {
				lastThrowable = tr;
				setState(State.startFailed);
			}
		}, "i2pdDaemonStart").start();
	}

	private Throwable lastThrowable;
	private String daemonStartResult = "N/A";

	private void fireStateUpdate1(State oldValue, State newValue) {
		Log.i(TAG, "daemon state change: " + state);
		for (StateUpdateListener listener : stateUpdateListeners) {
			try {
				listener.daemonStateUpdate(oldValue, newValue);
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

	public boolean isStartedOkay() {
		return getState().isStartedOkay();
	}

	public synchronized void stopDaemon() {
		if (isStartedOkay()) {
			try {
				I2PD_JNI.stopDaemon();
			} catch(Throwable tr) {
				Log.e(TAG, "", tr);
			}

			setState(State.stopped);
		}
	}

	private void processAssets() {
		if (!assetsCopied) {
			try {
				assetsCopied = true;

				File holderFile = new File(i2pdpath, "assets.ready");
				String versionName = BuildConfig.VERSION_NAME; // here will be app version, like 2.XX.XX
				StringBuilder text = new StringBuilder();

				if (holderFile.exists()) {
					try { // if holder file exists, read assets version string
						FileReader fileReader = new FileReader(holderFile);

						try {
							BufferedReader br = new BufferedReader(fileReader);

							try {
								String line;

								while ((line = br.readLine()) != null) {
									text.append(line);
								}
							}finally {
								try {
									br.close();
								} catch (IOException e) {
									Log.e(TAG, "", e);
								}
							}
						} finally {
							try {
								fileReader.close();
							} catch (IOException e) {
								Log.e(TAG, "", e);
							}
						}
					} catch (IOException e) {
						Log.e(TAG, "", e);
					}
				}

				// if version differs from current app version or null, try to delete certificates folder
				if (!text.toString().contains(versionName))
					try {
						boolean deleteResult = holderFile.delete();
						if (!deleteResult)
							Log.e(TAG, "holderFile.delete() returned " + deleteResult + ", absolute path='" + holderFile.getAbsolutePath() + "'");
						File certPath = new File(i2pdpath, "certificates");
						deleteRecursive(certPath);
					}
					catch (Throwable tr) {
						Log.e(TAG, "", tr);
					}

				// copy assets. If processed file exists, it won't be overwritten
				copyAsset("addressbook");
				copyAsset("certificates");
				copyAsset("tunnels.d");
				copyAsset("i2pd.conf");
				copyAsset("subscriptions.txt");
				copyAsset("tunnels.conf");

				// update holder file about successful copying
				FileWriter writer = new FileWriter(holderFile);
				try {
					writer.append(versionName);
				} finally {
					try {
						writer.close();
					} catch (IOException e) {
						Log.e(TAG,"on writer close", e);
					}
				}
			}
			catch (Throwable tr)
			{
				Log.e(TAG,"on assets copying", tr);
			}
		}
	}

	/**
	 * Copy the asset at the specified path to this app's data directory. If the
	 * asset is a directory, its contents are also copied.
	 *
	 * @param path
	 * Path to asset, relative to app's assets directory.
	 */
	private void copyAsset(String path) {
		// If we have a directory, we make it and recurse. If a file, we copy its
		// contents.
		try {
			String[] contents = assetManager.list(path);

			// The documentation suggests that list throws an IOException, but doesn't
			// say under what conditions. It'd be nice if it did so when the path was
			// to a file. That doesn't appear to be the case. If the returned array is
			// null or has 0 length, we assume the path is to a file. This means empty
			// directories will get turned into files.
			if (contents == null || contents.length == 0) {
				copyFileAsset(path);
				return;
			}

			// Make the directory.
			File dir = new File(i2pdpath, path);
			boolean result = dir.mkdirs();
			Log.d(TAG, "dir.mkdirs() returned " + result);

			// Recurse on the contents.
			for (String entry : contents) {
				copyAsset(path + '/' + entry);
			}
		} catch (IOException e) {
			Log.e(TAG, "ex ignored for path='" + path + "'", e);
		}
	}

	/**
	 * Copy the asset file specified by path to app's data directory. Assumes
	 * parent directories have already been created.
	 *
	 * @param path
	 * Path to asset, relative to app's assets directory.
	 */
	private void copyFileAsset(String path) {
		File file = new File(i2pdpath, path);
		if (!file.exists()) {
			try {
				try (InputStream in = assetManager.open(path)) {
					try (OutputStream out = new FileOutputStream(file)) {
						byte[] buffer = new byte[1024];
						int read = in.read(buffer);
						while (read != -1) {
							out.write(buffer, 0, read);
							read = in.read(buffer);
						}
					}
				}
			} catch (IOException e) {
				Log.e(TAG, "", e);
			}
		}
	}

	private void deleteRecursive(File fileOrDirectory) {
		if (fileOrDirectory.isDirectory()) {
			File[] files = fileOrDirectory.listFiles();
			if (files != null) {
				for (File child : files) {
					deleteRecursive(child);
				}
			}
		}
		boolean deleteResult = fileOrDirectory.delete();
		if (!deleteResult)
			Log.e(TAG, "fileOrDirectory.delete() returned " + deleteResult + ", absolute path='" + fileOrDirectory.getAbsolutePath() + "'");
	}

	private void registerNetworkCallback(){
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) registerNetworkCallback0();
	}

	@TargetApi(Build.VERSION_CODES.M)
	private void registerNetworkCallback0() {
		NetworkRequest request = new NetworkRequest.Builder()
				.addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
				.build();
		NetworkStateCallbackImpl networkCallback = new NetworkStateCallbackImpl();
		connectivityManager.registerNetworkCallback(request, networkCallback);
	}

	@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
	private static final class NetworkStateCallbackImpl extends ConnectivityManager.NetworkCallback {
		@Override
		public void onAvailable(Network network) {
			super.onAvailable(network);
			I2PD_JNI.onNetworkStateChanged(true);
			Log.i(TAG, "NetworkCallback.onAvailable");
		}

		@Override
		public void onLost(Network network) {
			super.onLost(network);
			I2PD_JNI.onNetworkStateChanged(false);
			Log.i(TAG, " NetworkCallback.onLost");
		}
	}
}
