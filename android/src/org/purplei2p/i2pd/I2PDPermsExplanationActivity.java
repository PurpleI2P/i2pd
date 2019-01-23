package org.purplei2p.i2pd;

import android.app.ActionBar;
import android.content.Intent;
import android.os.Bundle;
import android.app.Activity;
import android.view.View;
import android.widget.Button;

public class I2PDPermsExplanationActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_perms_explanation);
		ActionBar actionBar = getActionBar();
		if(actionBar!=null)actionBar.setHomeButtonEnabled(false);
		Button button_ok = (Button) findViewById(R.id.button_ok);
		button_ok.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View view) {
				returnFromActivity();
			}
		});
	}

	private void returnFromActivity() {
		Intent data = new Intent();
		Activity parent = getParent();
		if (parent == null) {
			setResult(Activity.RESULT_OK, data);
		} else {
			parent.setResult(Activity.RESULT_OK, data);
		}
		finish();
	}

}
