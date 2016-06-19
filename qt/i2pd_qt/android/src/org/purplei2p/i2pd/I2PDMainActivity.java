package org.purplei2p.i2pd;

import org.qtproject.qt5.android.bindings.QtActivity;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;

public class I2PDMainActivity extends QtActivity
{

	private static I2PDMainActivity instance;

	public I2PDMainActivity() {}

	/* (non-Javadoc)
	 * @see org.qtproject.qt5.android.bindings.QtActivity#onCreate(android.os.Bundle)
	 */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		I2PDMainActivity.setInstance(this);
		super.onCreate(savedInstanceState);
		
		//set the app be foreground (do not unload when RAM needed)
		doBindService();
	}

	/* (non-Javadoc)
	 * @see org.qtproject.qt5.android.bindings.QtActivity#onDestroy()
	 */
	@Override
	protected void onDestroy() {
		I2PDMainActivity.setInstance(null);
	    doUnbindService();
		super.onDestroy();
	}

	public static I2PDMainActivity getInstance() {
		return instance;
	}

	private static void setInstance(I2PDMainActivity instance) {
		I2PDMainActivity.instance = instance;
	}
	
	

//	private LocalService mBoundService;

	private ServiceConnection mConnection = new ServiceConnection() {
	    public void onServiceConnected(ComponentName className, IBinder service) {
	        // This is called when the connection with the service has been
	        // established, giving us the service object we can use to
	        // interact with the service.  Because we have bound to a explicit
	        // service that we know is running in our own process, we can
	        // cast its IBinder to a concrete class and directly access it.
//	        mBoundService = ((LocalService.LocalBinder)service).getService();

	        // Tell the user about this for our demo.
//	        Toast.makeText(Binding.this, R.string.local_service_connected,
//	                Toast.LENGTH_SHORT).show();
	    }

	    public void onServiceDisconnected(ComponentName className) {
	        // This is called when the connection with the service has been
	        // unexpectedly disconnected -- that is, its process crashed.
	        // Because it is running in our same process, we should never
	        // see this happen.
//	        mBoundService = null;
//	        Toast.makeText(Binding.this, R.string.local_service_disconnected,
//	                Toast.LENGTH_SHORT).show();
	    }
	};

	private boolean mIsBound;

	private void doBindService() {
	    // Establish a connection with the service.  We use an explicit
	    // class name because we want a specific service implementation that
	    // we know will be running in our own process (and thus won't be
	    // supporting component replacement by other applications).
	    bindService(new Intent(this, 
	            LocalService.class), mConnection, Context.BIND_AUTO_CREATE);
	    mIsBound = true;
	}

	void doUnbindService() {
	    if (mIsBound) {
	        // Detach our existing connection.
	        unbindService(mConnection);
	        mIsBound = false;
	    }
	}
}
