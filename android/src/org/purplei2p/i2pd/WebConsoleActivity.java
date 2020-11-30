package org.purplei2p.i2pd;

import android.app.Activity;
import android.os.Bundle;
import android.view.MenuItem;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.util.Objects;

public class WebConsoleActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web_console);

        Objects.requireNonNull(getActionBar()).setDisplayHomeAsUpEnabled(true);

        final WebView webView = findViewById(R.id.webview1);
        webView.setWebViewClient(new WebViewClient());

        final WebSettings webSettings = webView.getSettings();
        webSettings.setBuiltInZoomControls(true);
        webSettings.setJavaScriptEnabled(false);
        webView.loadUrl("http://127.0.0.1:7070"); // TODO: instead 7070 I2Pd....HttpPort
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id==android.R.id.home) {
            finish();
            return true;
        }
        return false;
    }
}
