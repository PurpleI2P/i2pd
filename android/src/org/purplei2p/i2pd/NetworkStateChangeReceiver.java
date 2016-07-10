package org.purplei2p.i2pd;

import android.util.Log;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;

public class NetworkStateChangeReceiver extends BroadcastReceiver {

    private static final String TAG = "i2pd";

	//api level 1
    @Override
    public void onReceive(final Context context, final Intent intent) {
        Log.d(TAG,"Network state change");
		try {
			ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
			NetworkInfo activeNetworkInfo = cm.getActiveNetworkInfo();
			boolean isConnected = activeNetworkInfo!=null && activeNetworkInfo.isConnected();
			// https://developer.android.com/training/monitoring-device-state/connectivity-monitoring.html?hl=ru
			// boolean isWiFi = activeNetworkInfo!=null && (activeNetworkInfo.getType() == ConnectivityManager.TYPE_WIFI);

			I2PD_JNI.onNetworkStateChanged(isConnected);
		} catch (Throwable tr) {
			Log.d(TAG,"",tr);
		}
    }
}
