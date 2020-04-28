package org.purplei2p.i2pd;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Timer;
import java.util.TimerTask;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.os.Environment;
import android.os.IBinder;
import android.os.PowerManager;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;


import androidx.annotation.NonNull;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

// For future package update checking

import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;


import static android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS;

public class I2PDActivity extends Activity {
	private WebView webView;

	private static final String TAG = "i2pdActvt";
	private static final int MY_PERMISSION_REQUEST_WRITE_EXTERNAL_STORAGE = 1;
	public static final int GRACEFUL_DELAY_MILLIS = 10 * 60 * 1000;
	public static final String PACKAGE_URI_SCHEME = "package:";

	private TextView textView;
	private boolean assetsCopied;
	private String i2pdpath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/i2pd/";
	//private ConfigParser parser = new ConfigParser(i2pdpath); // TODO:

	private static final DaemonSingleton daemon = DaemonSingleton.getInstance();

	private final DaemonSingleton.StateUpdateListener daemonStateUpdatedListener = new DaemonSingleton.StateUpdateListener() {
		@Override
		public void daemonStateUpdate() {
			processAssets();
			runOnUiThread(() -> {
				try {
					if (textView == null)
						return;
					Throwable tr = daemon.getLastThrowable();
					if (tr!=null) {
						textView.setText(throwableToString(tr));
						return;
					}
					DaemonSingleton.State state = daemon.getState();
					String startResultStr = DaemonSingleton.State.startFailed.equals(state) ? String.format(": %s", daemon.getDaemonStartResult()) : "";
					String graceStr = DaemonSingleton.State.gracefulShutdownInProgress.equals(state) ? String.format(": %s %s", formatGraceTimeRemaining(), getText(R.string.remaining)) : "";
					textView.setText(String.format("%s%s%s", getText(state.getStatusStringResourceId()), startResultStr, graceStr));
				} catch (Throwable tr) {
					Log.e(TAG,"error ignored",tr);
				}
			});
		}
	};
	private static volatile long graceStartedMillis;
	private static final Object graceStartedMillis_LOCK = new Object();
	private Menu optionsMenu;

	private static String formatGraceTimeRemaining() {
		long remainingSeconds;
		synchronized (graceStartedMillis_LOCK) {
			remainingSeconds = Math.round(Math.max(0, graceStartedMillis + GRACEFUL_DELAY_MILLIS - System.currentTimeMillis()) / 1000.0D);
		}
		long remainingMinutes = (long)Math.floor(remainingSeconds / 60.0D);
		long remSec = remainingSeconds - remainingMinutes * 60;
		return remainingMinutes + ":" + (remSec / 10) + remSec % 10;
	}

	@Override
	public void onCreate(Bundle savedInstanceState) {
		Log.i(TAG, "onCreate");
		super.onCreate(savedInstanceState);

		textView = new TextView(this);
		setContentView(textView);
		daemon.addStateChangeListener(daemonStateUpdatedListener);
		daemonStateUpdatedListener.daemonStateUpdate();

		 // request permissions
		if (Build.VERSION.SDK_INT >= 23) {
			if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
				ActivityCompat.requestPermissions(this,
					new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
					MY_PERMISSION_REQUEST_WRITE_EXTERNAL_STORAGE);
			}
		}

		// set the app be foreground
		doBindService();

		final Timer gracefulQuitTimer = getGracefulQuitTimer();
		if (gracefulQuitTimer != null) {
			long gracefulStopAtMillis;
			synchronized (graceStartedMillis_LOCK) {
				gracefulStopAtMillis = graceStartedMillis + GRACEFUL_DELAY_MILLIS;
			}
			rescheduleGraceStop(gracefulQuitTimer, gracefulStopAtMillis);
		}

		openBatteryOptimizationDialogIfNeeded();
	}

	@Override
	protected void onDestroy() {
		super.onDestroy();
		textView = null;
		daemon.removeStateChangeListener(daemonStateUpdatedListener);
		//cancelGracefulStop0();
		try {
			doUnbindService();
		} catch(Throwable tr) {
			Log.e(TAG, "", tr);
		}
	}

	@Override
	public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults)
	{
		if (requestCode == MY_PERMISSION_REQUEST_WRITE_EXTERNAL_STORAGE) {
			if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED)
				Log.e(TAG, "WR_EXT_STORAGE perm granted");
			else {
				Log.e(TAG, "WR_EXT_STORAGE perm declined, stopping i2pd");
				i2pdStop();
				//TODO must work w/o this perm, ask orignal
			}
		}
	}

	private void cancelGracefulStop0() {
		Timer gracefulQuitTimer = getGracefulQuitTimer();
		if (gracefulQuitTimer != null) {
			gracefulQuitTimer.cancel();
			setGracefulQuitTimer(null);
		}
	}

	private CharSequence throwableToString(Throwable tr) {
		StringWriter sw = new StringWriter(8192);
		PrintWriter pw = new PrintWriter(sw);
		tr.printStackTrace(pw);
		pw.close();
		return sw.toString();
	}

	// private LocalService mBoundService;

	private ServiceConnection mConnection = new ServiceConnection() {
		public void onServiceConnected(ComponentName className, IBinder service) {
			// This is called when the connection with the service has been
			// established, giving us the service object we can use to
			// interact with the service.  Because we have bound to a explicit
			// service that we know is running in our own process, we can
			// cast its IBinder to a concrete class and directly access it.
			//		mBoundService = ((LocalService.LocalBinder)service).getService();

			// Tell the user about this for our demo.
			//		Toast.makeText(Binding.this, R.string.local_service_connected,
			//		Toast.LENGTH_SHORT).show();
		}

		public void onServiceDisconnected(ComponentName className) {
			// This is called when the connection with the service has been
			// unexpectedly disconnected -- that is, its process crashed.
			// Because it is running in our same process, we should never
			// see this happen.
			//		mBoundService = null;
			//		Toast.makeText(Binding.this, R.string.local_service_disconnected,
			//		Toast.LENGTH_SHORT).show();
		}
	};

	private static volatile boolean mIsBound;

	private void doBindService() {
		synchronized (I2PDActivity.class) {
			if (mIsBound)
				return;
			// Establish a connection with the service.  We use an explicit
			// class name because we want a specific service implementation that
			// we know will be running in our own process (and thus won't be
			// supporting component replacement by other applications).
			bindService(new Intent(this, ForegroundService.class), mConnection, Context.BIND_AUTO_CREATE);
			mIsBound = true;
		}
	}

	private void doUnbindService() {
		synchronized (I2PDActivity.class) {
			if (mIsBound) {
				// Detach our existing connection.
				unbindService(mConnection);
				mIsBound = false;
			}
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.options_main, menu);
		menu.findItem(R.id.action_battery_otimizations).setVisible(isBatteryOptimizationsOpenOsDialogApiAvailable());
		this.optionsMenu = menu;
		return true;
	}

	private boolean isBatteryOptimizationsOpenOsDialogApiAvailable() {
		return android.os.Build.VERSION.SDK_INT >= 23;
	}

	@Override
	public boolean onOptionsItemSelected(@NonNull MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();

		switch(id) {
			case R.id.action_stop:
				i2pdStop();
				return true;

			case R.id.action_graceful_stop:
				synchronized (graceStartedMillis_LOCK) {
					if (getGracefulQuitTimer() != null)
						cancelGracefulStop();
					else
						i2pdGracefulStop();
				}
				return true;

			case R.id.action_battery_otimizations:
				onActionBatteryOptimizations();
				return true;

			case R.id.action_reload_tunnels_config:
				onReloadTunnelsConfig();
				return true;

			case R.id.action_start_webview:
				setContentView(R.layout.webview);
				this.webView = (WebView) findViewById(R.id.webview1);
				this.webView.setWebViewClient(new WebViewClient());

				WebSettings webSettings = this.webView.getSettings();
				webSettings.setBuiltInZoomControls(true);
				webSettings.setJavaScriptEnabled(false);
				this.webView.loadUrl("http://127.0.0.1:7070"); // TODO: instead 7070 I2Pd....HttpPort
				break;
		}

		return super.onOptionsItemSelected(item);
	}

	private void onActionBatteryOptimizations() {
		if (isBatteryOptimizationsOpenOsDialogApiAvailable()) {
			try {
				startActivity(new Intent(ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
			} catch (ActivityNotFoundException e) {
				Log.e(TAG, "BATT_OPTIM_DIALOG_ActvtNotFound", e);
				Toast.makeText(this, R.string.os_version_does_not_support_battery_optimizations_show_os_dialog_api, Toast.LENGTH_SHORT).show();
			}
		}
	}

	private void onReloadTunnelsConfig() {
		Log.d(TAG, "reloading tunnels");
		daemon.reloadTunnelsConfigs();
		Toast.makeText(this, R.string.tunnels_reloading, Toast.LENGTH_SHORT).show();
	}

	private void i2pdStop() {
		cancelGracefulStop0();
		new Thread(() -> {
			Log.d(TAG, "stopping");
			try {
				daemon.stopDaemon();
			} catch (Throwable tr) {
				Log.e(TAG, "", tr);
			}
			quit(); //TODO make menu items for starting i2pd. On my Android, I need to reboot the OS to restart i2pd.
		}, "stop").start();
	}

	private static volatile Timer gracefulQuitTimer;

	private void i2pdGracefulStop() {
		if (daemon.getState() == DaemonSingleton.State.stopped) {
			Toast.makeText(this, R.string.already_stopped, Toast.LENGTH_SHORT).show();
			return;
		}
		if (getGracefulQuitTimer() != null) {
			Toast.makeText(this, R.string.graceful_stop_is_already_in_progress, Toast.LENGTH_SHORT).show();
			return;
		}
		Toast.makeText(this, R.string.graceful_stop_is_in_progress, Toast.LENGTH_SHORT).show();
		new Thread(() -> {
			try {
				Log.d(TAG, "graceful stopping");
				if (daemon.isStartedOkay()) {
					daemon.stopAcceptingTunnels();
					long gracefulStopAtMillis;
					synchronized (graceStartedMillis_LOCK) {
						graceStartedMillis = System.currentTimeMillis();
						gracefulStopAtMillis = graceStartedMillis + GRACEFUL_DELAY_MILLIS;
					}
					rescheduleGraceStop(null, gracefulStopAtMillis);
				} else
					i2pdStop();
			} catch(Throwable tr) {
				Log.e(TAG, "", tr);
			}
		}, "gracInit").start();
	}

	private void cancelGracefulStop()
	{
		cancelGracefulStop0();
		new Thread(() -> {
			try {
				Log.d(TAG, "canceling graceful stop");
				if (daemon.isStartedOkay()) {
					daemon.startAcceptingTunnels();
					runOnUiThread(() -> Toast.makeText(this, R.string.shutdown_canceled, Toast.LENGTH_SHORT).show());
				} else
					i2pdStop();
			} catch(Throwable tr) {
				Log.e(TAG, "", tr);
			}
		}, "gracCancel").start();
	}

	private void rescheduleGraceStop(Timer gracefulQuitTimerOld, long gracefulStopAtMillis) {
		if (gracefulQuitTimerOld != null)
			gracefulQuitTimerOld.cancel();

		if(daemon.GetTransitTunnelsCount() <= 0) { // no tunnels left
			Log.d(TAG, "no transit tunnels left, stopping");
			i2pdStop();
		}

		final Timer gracefulQuitTimer = new Timer(true);
		setGracefulQuitTimer(gracefulQuitTimer);
		gracefulQuitTimer.schedule(new TimerTask() {

			@Override
			public void run() {
				i2pdStop();
			}

		}, Math.max(0, gracefulStopAtMillis - System.currentTimeMillis()));
		final TimerTask tickerTask = new TimerTask() {
			@Override
			public void run() {
				daemonStateUpdatedListener.daemonStateUpdate();
			}
		};
		gracefulQuitTimer.scheduleAtFixedRate(tickerTask, 0/*start delay*/, 1000/*millis period*/);
	}

	private static Timer getGracefulQuitTimer() {
		return gracefulQuitTimer;
	}

	private void setGracefulQuitTimer(Timer gracefulQuitTimer) {
		I2PDActivity.gracefulQuitTimer = gracefulQuitTimer;
		runOnUiThread(()-> {
			Menu menu = optionsMenu;
			if (menu != null) {
				MenuItem item = menu.findItem(R.id.action_graceful_stop);
				if (item != null) {
					synchronized (graceStartedMillis_LOCK) {
						item.setTitle(getGracefulQuitTimer() != null ? R.string.action_cancel_graceful_stop : R.string.action_graceful_stop);
					}
				}
			}
		});
	}

	/**
		* Copy the asset at the specified path to this app's data directory. If the
		* asset is a directory, its contents are also copied.
		*
		* @param path
		* Path to asset, relative to app's assets directory.
	*/
	private void copyAsset(String path) {
		AssetManager manager = getAssets();

		// If we have a directory, we make it and recurse. If a file, we copy its
		// contents.
		try {
			String[] contents = manager.list(path);

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
				try (InputStream in = getAssets().open(path)) {
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

	private void processAssets() {
		if (!assetsCopied) {
			try {
				assetsCopied = true; // prevent from running on every state update

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

	@SuppressLint("BatteryLife")
	private void openBatteryOptimizationDialogIfNeeded() {
		boolean questionEnabled = getPreferences().getBoolean(getBatteryOptimizationPreferenceKey(), true);
		Log.i(TAG, "BATT_OPTIM_questionEnabled==" + questionEnabled);
		if (!isKnownIgnoringBatteryOptimizations()
				&& android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M
				&& questionEnabled) {
			AlertDialog.Builder builder = new AlertDialog.Builder(this);
			builder.setTitle(R.string.battery_optimizations_enabled);
			builder.setMessage(R.string.battery_optimizations_enabled_dialog);
			builder.setPositiveButton(R.string.continue_str, (dialog, which) -> {
				try {
					startActivity(new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse(PACKAGE_URI_SCHEME + getPackageName())));
				} catch (ActivityNotFoundException e) {
					Log.e(TAG, "BATT_OPTIM_ActvtNotFound", e);
					Toast.makeText(this, R.string.device_does_not_support_disabling_battery_optimizations, Toast.LENGTH_SHORT).show();
				}
			});
			builder.setOnDismissListener(dialog -> setNeverAskForBatteryOptimizationsAgain());
			final AlertDialog dialog = builder.create();
			dialog.setCanceledOnTouchOutside(false);
			dialog.show();
		}
	}

	private void setNeverAskForBatteryOptimizationsAgain() {
		getPreferences().edit().putBoolean(getBatteryOptimizationPreferenceKey(), false).apply();
	}

	protected boolean isKnownIgnoringBatteryOptimizations() {
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
			final PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
			if (pm == null) {
				Log.i(TAG, "BATT_OPTIM: POWER_SERVICE==null");
				return false;
			}
			boolean ignoring = pm.isIgnoringBatteryOptimizations(getPackageName());
			Log.i(TAG, "BATT_OPTIM: ignoring==" + ignoring);
			return ignoring;
		} else {
			Log.i(TAG, "BATT_OPTIM: old sdk version==" + Build.VERSION.SDK_INT);
			return false;
		}
	}

	protected SharedPreferences getPreferences() {
		return PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
	}

	private String getBatteryOptimizationPreferenceKey() {
		@SuppressLint("HardwareIds") String device = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
		return "show_battery_optimization" + (device == null ? "" : device);
	}

	private void quit() {
		try {
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
				finishAndRemoveTask();
			} else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
				finishAffinity();
			} else {
				//moveTaskToBack(true);
				finish();
			}
		} catch (Throwable tr) {
			Log.e(TAG, "", tr);
		}
		try {
			daemon.stopDaemon();
		} catch (Throwable tr) {
			Log.e(TAG, "", tr);
		}
		System.exit(0);
	}
}
