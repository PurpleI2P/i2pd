package org.purplei2p.i2pd;

import android.app.Activity;
import android.widget.TextView;
import android.os.Bundle;

public class I2PD extends Activity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView  tv = new TextView(this);
        tv.setText( "libi2pd.so was compiled with ABI " + getABICompiledWith());
        setContentView(tv);
    }

    public String getABICompiledWith() {
    	return I2PD_JNI.getABICompiledWith();
    }
}
