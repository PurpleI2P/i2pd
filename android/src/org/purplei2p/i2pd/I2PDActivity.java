package org.purplei2p.i2pd;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Timer;
import java.util.TimerTask;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

public class I2PDActivity extends Activity {
    private static final String TAG = "i2pdActvt";
    public static final int GRACEFUL_DELAY_MILLIS = 10 * 60 * 1000;

    private TextView textView;

	private static final DaemonSingleton daemon = DaemonSingleton.getInstance();

	private final DaemonSingleton.StateUpdateListener daemonStateUpdatedListener =
			new DaemonSingleton.StateUpdateListener() {

		@Override
		public void daemonStateUpdate() {
			runOnUiThread(new Runnable(){

				@Override
				public void run() {
					try {
						if(textView==null)return;
						Throwable tr = daemon.getLastThrowable();
						if(tr!=null) {
							textView.setText(throwableToString(tr));
							return;
						}
						DaemonSingleton.State state = daemon.getState();
						textView.setText(
						        String.valueOf(state)+
                                    (DaemonSingleton.State.startFailed.equals(state)?": "+daemon.getDaemonStartResult():"")+
                                    (DaemonSingleton.State.gracefulShutdownInProgress.equals(state)?":  "+formatGraceTimeRemaining()+" "+getText(R.string.remaining):"")
                        );
					} catch (Throwable tr) {
						Log.e(TAG,"error ignored",tr);
					}
				}
			});
		}
	};
    private static volatile long graceStartedMillis;
    private static final Object graceStartedMillis_LOCK=new Object();

    private static String formatGraceTimeRemaining() {
        long remainingSeconds;
        synchronized (graceStartedMillis_LOCK){
            remainingSeconds=Math.round(Math.max(0,graceStartedMillis+GRACEFUL_DELAY_MILLIS-System.currentTimeMillis())/1000.0D);
        }
        long remainingMinutes=(long)Math.floor(remainingSeconds/60.0D);
        long remSec=remainingSeconds-remainingMinutes*60;
        return remainingMinutes+":"+(remSec/10)+remSec%10;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        textView = new TextView(this);
        setContentView(textView);
        daemon.addStateChangeListener(daemonStateUpdatedListener);
        daemonStateUpdatedListener.daemonStateUpdate();

        //set the app be foreground
        doBindService();

        final Timer gracefulQuitTimer = getGracefulQuitTimer();
        if(gracefulQuitTimer!=null){
            long gracefulStopAtMillis;
            synchronized (graceStartedMillis_LOCK) {
                gracefulStopAtMillis = graceStartedMillis + GRACEFUL_DELAY_MILLIS;
            }
            rescheduleGraceStop(gracefulQuitTimer, gracefulStopAtMillis);
        }
    }

    @Override
	protected void onDestroy() {
		super.onDestroy();
        textView = null;
        daemon.removeStateChangeListener(daemonStateUpdatedListener);
        //cancelGracefulStop();
		try{
            doUnbindService();
		}catch(Throwable tr){
			Log.e(TAG, "", tr);
		}
	}

    private static void cancelGracefulStop() {
        Timer gracefulQuitTimer = getGracefulQuitTimer();
        if(gracefulQuitTimer!=null) {
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


    private static volatile boolean mIsBound;

    private void doBindService() {
        synchronized (I2PDActivity.class) {
            if (mIsBound) return;
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
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();

		switch(id){
        case R.id.action_stop:
            i2pdStop();
            return true;
        case R.id.action_graceful_stop:
            i2pdGracefulStop();
            return true;
        }

		return super.onOptionsItemSelected(item);
	}

	private void i2pdStop() {
        cancelGracefulStop();
        new Thread(new Runnable(){

            @Override
            public void run() {
                Log.d(TAG, "stopping");
                try{
                    daemon.stopDaemon();
                }catch (Throwable tr) {
                    Log.e(TAG, "", tr);
                }
            }

        },"stop").start();
    }

    private static volatile Timer gracefulQuitTimer;

    private void i2pdGracefulStop() {
        if(daemon.getState()==DaemonSingleton.State.stopped){
            Toast.makeText(this, R.string.already_stopped,
                    Toast.LENGTH_SHORT).show();
            return;
        }
    	if(getGracefulQuitTimer()!=null){
	        Toast.makeText(this, R.string.graceful_stop_is_already_in_progress,
	        		Toast.LENGTH_SHORT).show();
    		return;
    	}
        Toast.makeText(this, R.string.graceful_stop_is_in_progress,
        		Toast.LENGTH_SHORT).show();
        new Thread(new Runnable(){

			@Override
			public void run() {
				try{
					Log.d(TAG, "grac stopping");
			        if(daemon.isStartedOkay()) {
			        	daemon.stopAcceptingTunnels();
                        long gracefulStopAtMillis;
                        synchronized (graceStartedMillis_LOCK) {
                            graceStartedMillis = System.currentTimeMillis();
                            gracefulStopAtMillis = graceStartedMillis + GRACEFUL_DELAY_MILLIS;
                        }
                        rescheduleGraceStop(null,gracefulStopAtMillis);
			        }else{
			        	i2pdStop();
			        }
				} catch(Throwable tr) {
					Log.e(TAG,"",tr);
				}
			}

        },"gracInit").start();
    }

    private void rescheduleGraceStop(Timer gracefulQuitTimerOld, long gracefulStopAtMillis) {
        if(gracefulQuitTimerOld!=null)gracefulQuitTimerOld.cancel();
        final Timer gracefulQuitTimer = new Timer(true);
        setGracefulQuitTimer(gracefulQuitTimer);
        gracefulQuitTimer.schedule(new TimerTask(){

            @Override
            public void run() {
                i2pdStop();
            }

        }, Math.max(0,gracefulStopAtMillis-System.currentTimeMillis()));
        final TimerTask tickerTask = new TimerTask() {
            @Override
            public void run() {
                daemonStateUpdatedListener.daemonStateUpdate();
            }
        };
        gracefulQuitTimer.scheduleAtFixedRate(tickerTask,0/*start delay*/,1000/*millis period*/);
    }

    private static Timer getGracefulQuitTimer() {
        return gracefulQuitTimer;
	}

	private static void setGracefulQuitTimer(Timer gracefulQuitTimer) {
   		I2PDActivity.gracefulQuitTimer = gracefulQuitTimer;
	}
}
