package com.onlyicing.dnsconsole;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Hosts the existing DNS Console web UI in a WebView. The Python engine is the
 * repo's own advanced_core.py, started on a loopback port; the WebView simply
 * points at it. No UI is reimplemented here.
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "DnsConsole";
    private static final String PY_MODULE = "advanced_core";
    private static final int BASE_PORT = 8765;

    private WebView webView;
    private volatile int port = BASE_PORT;
    private volatile boolean serverStarted = false;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setAllowFileAccess(false);
        s.setCacheMode(WebSettings.LOAD_DEFAULT);
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
                return false; // keep everything inside the app
            }
        });
        setContentView(webView);

        // Back button: go back in the WebView history before leaving the app.
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (webView.canGoBack()) {
                    webView.goBack();
                } else {
                    setEnabled(false);
                    getOnBackPressedDispatcher().onBackPressed();
                }
            }
        });

        webView.loadData("<html><body style='background:#0b0a16;color:#cfc9ff;"
                + "font-family:monospace;padding:24px'>Starting Python engine…</body></html>",
                "text/html", "utf-8");

        new Thread(this::startPythonServer, "dns-server-start").start();
    }

    private void startPythonServer() {
        try {
            if (!Python.isStarted()) {
                Python.start(new AndroidPlatform(getApplicationContext()));
            }
            Python py = Python.getInstance();

            // Reuse the script's own free-port finder so Java and Python agree.
            PyObject module = py.getModule(PY_MODULE);
            int chosen;
            try {
                chosen = module.callAttr("_web_pick_port", "127.0.0.1", BASE_PORT).toInt();
            } catch (Throwable t) {
                chosen = BASE_PORT;
            }
            port = chosen;

            // launch_web_console() blocks in serve_forever(), so it must own its
            // own thread; this thread then waits until the port answers.
            Thread serverThread = new Thread(() -> {
                try {
                    module.callAttr(
                            "launch_web_console",
                            (Object[]) new String[]{"--host", "127.0.0.1", "--port",
                                    String.valueOf(port), "--no-open"});
                } catch (Throwable t) {
                    Log.e(TAG, "Python server thread exited", t);
                }
            }, "dns-python-server");
            serverThread.setDaemon(true);
            serverThread.start();

            serverStarted = true;
            Log.i(TAG, "Python web console starting on 127.0.0.1:" + port);
            waitForServerThenLoad();
        } catch (Throwable t) {
            Log.e(TAG, "Failed to start Python server", t);
            runOnUiThread(() -> {
                Toast.makeText(this, "Engine failed to start: " + t.getMessage(),
                        Toast.LENGTH_LONG).show();
                webView.loadData("<html><body style='background:#1b0a12;color:#ff9ec0;"
                        + "font-family:monospace;padding:24px'>Engine failed:<br>"
                        + android.text.TextUtils.htmlEncode(String.valueOf(t))
                        + "</body></html>", "text/html", "utf-8");
            });
        }
    }

    private void waitForServerThenLoad() {
        String url = "http://127.0.0.1:" + port + "/";
        for (int i = 0; i < 200; i++) { // up to ~20s
            if (isReachable(url + "api/health")) {
                runOnUiThread(() -> webView.loadUrl(url));
                return;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        runOnUiThread(() -> webView.loadUrl(url));
    }

    private boolean isReachable(String url) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(500);
            c.setReadTimeout(500);
            c.setRequestMethod("GET");
            int code = c.getResponseCode();
            c.disconnect();
            return code == 200;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        // The Python server thread is daemon-like; the process dies with the task.
    }
}
