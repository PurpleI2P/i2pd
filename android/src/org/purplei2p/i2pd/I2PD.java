package org.purplei2p.i2pd;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Timer;
import java.util.TimerTask;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

public class I2PD extends Activity {
	private static final String TAG = "i2pd";
	
	private static Throwable loadLibsThrowable;
	static {
		try {
			I2PD_JNI.loadLibraries();
		} catch (Throwable tr) {
			loadLibsThrowable = tr;
		}
	}
	private String daemonStartResult="N/A";
	private boolean destroyed=false;
	private TextView textView;
	
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        destroyed=false;

        //set the app be foreground (do not unload when RAM needed)
        doBindService();

        textView = new TextView(this);
        setContentView(textView);
        if (loadLibsThrowable != null) {
        	textView.setText(throwableToString(loadLibsThrowable)+"\r\n");
        	return;
        }
        try {
        	textView.setText( 
        			"libi2pd.so was compiled with ABI " + getABICompiledWith() + "\r\n"+
        			"Starting daemon... ");
        	new Thread(new Runnable(){

				@Override
				public void run() {
			        try {
						doStartDaemon();
			        } catch (final Throwable tr) {
						appendThrowable(tr);
			        }
				}
        		
        	},"i2pdDaemonStarting").start();
        } catch (Throwable tr) {
        	textView.setText(textView.getText().toString()+throwableToString(tr));
        }
    }

    @Override
	protected void onDestroy() {
		super.onDestroy();
		localDestroy();
	}

	private synchronized void localDestroy() {
		if(destroyed)return;
		destroyed=true;
		if(gracefulQuitTimer!=null) {
			gracefulQuitTimer.cancel();
			gracefulQuitTimer = null;
		}
		try{
            doUnbindService();
		}catch(Throwable tr){
			Log.e(TAG, "", tr);
		}
		if("ok".equals(daemonStartResult)) {
	        try {
	        	I2PD_JNI.stopDaemon();
	        } catch (Throwable tr) {
	        	Log.e(TAG, "error", tr);
	        }
		}
	}

	private CharSequence throwableToString(Throwable tr) {
    	StringWriter sw = new StringWriter(8192);
    	PrintWriter pw = new PrintWriter(sw);
    	tr.printStackTrace(pw);
    	pw.close();
    	return sw.toString();
	}

	public String getABICompiledWith() {
    	return I2PD_JNI.getABICompiledWith();
    }

	private synchronized void doStartDaemon() {
		if(destroyed)return;
		daemonStartResult = I2PD_JNI.startDaemon();
		runOnUiThread(new Runnable(){

			@Override
			public void run() {
				synchronized (I2PD.this) {
					if(destroyed)return;
					textView.setText(
        					textView.getText().toString()+
        					"start result: "+daemonStartResult+"\r\n"
        			);
				}	
			}
    		
    	});
	}

	private void appendThrowable(final Throwable tr) {
		runOnUiThread(new Runnable(){

			@Override
			public void run() {
				synchronized (I2PD.this) {
					if(destroyed)return;
					textView.setText(textView.getText().toString()+throwableToString(tr)+"\r\n");
				}
			}
		});
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
                ForegroundService.class), mConnection, Context.BIND_AUTO_CREATE);
        mIsBound = true;
    }

    private void doUnbindService() {
        if (mIsBound) {
            // Detach our existing connection.
            unbindService(mConnection);
            mIsBound = false;
        }
    }

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.options_main, menu); 
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();

		switch(id){
        case R.id.action_quit:
            quit();
            return true;
        case R.id.action_graceful_quit:
            gracefulQuit();
            return true;
        }

		return super.onOptionsItemSelected(item);
	}

    @SuppressLint("NewApi")
	private void quit() {
        try {
            localDestroy();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                finishAndRemoveTask();
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                finishAffinity();
            } else {
                //moveTaskToBack(true);
                finish();
            }
        }catch (Throwable tr) {
            Log.e(TAG, "", tr);
        }
    }

    private Timer gracefulQuitTimer; 
    private synchronized void gracefulQuit() {
    	if(gracefulQuitTimer!=null){
	        Toast.makeText(this, R.string.graceful_quit_is_already_in_progress,
	        		Toast.LENGTH_SHORT).show();
    		return;
    	}
        Toast.makeText(this, R.string.graceful_quit_is_in_progress,
        		Toast.LENGTH_SHORT).show();
        new Thread(new Runnable(){

			@Override
			public void run() {
				try{
					synchronized (I2PD.this) {
				        if("ok".equals(daemonStartResult)) {
				        	I2PD_JNI.stopAcceptingTunnels();
				            gracefulQuitTimer = new Timer(true);
				            gracefulQuitTimer.schedule(new TimerTask(){

				    			@Override
				    			public void run() {
				    				quit();	
				    			}
				            	
				            }, 10*60*1000/*millis*/);
				        }else{
				        	quit();
				        }
					}
				} catch(Throwable tr) {
					Log.e(TAG,"",tr);
				}
			}
        	
        },"gracQuitInit").start();
    }
}
