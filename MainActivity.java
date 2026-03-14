package com.example.myapplication;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import android.util.Base64;

/**
 * MainActivity — Login & Signup with hardware-backed key pair.
 *
 * Key design
 * ──────────
 * • Algorithm : EC (P-256) — compact public key, fast on constrained hardware
 * • Alias     : KEYSTORE_ALIAS constant below
 * • Storage   : Android Keystore (private key never leaves secure hardware /
 *               StrongBox if the device has one)
 * • Transport : public key is Base64-encoded (DER/X.509) and sent in every
 *               POST body alongside username + password
 *
 * The server receives:
 *   { "username": "…", "password": "…", "publicKey": "<base64>" }
 *
 * Server-side you can store publicKey and later verify a challenge signed by
 * this client — password becomes optional once that flow is implemented.
 *
 * Change SERVER_URL to match your environment before running.
 */
public class MainActivity extends AppCompatActivity {

    // ── Configuration ────────────────────────────────────────────────────────
    private static final String SERVER_URL     = "http://192.168.31.216:8000";
    //  10.0.2.2    →  emulator alias for host localhost
    //  192.168.x.x →  real device on same Wi-Fi as your PC

    private static final String KEYSTORE_ALIAS   = "authclient_ec_key";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    // ── UI ───────────────────────────────────────────────────────────────────
    private EditText    etUsername, etPassword;
    private Button      btnLogin, btnSignup;
    private TextView    tvStatus, tvKeyInfo;
    private ProgressBar progressBar;

    // ── Threading ────────────────────────────────────────────────────────────
    private final ExecutorService executor    = Executors.newSingleThreadExecutor();
    private final Handler         mainHandler = new Handler(Looper.getMainLooper());

    // ── Cached public key (loaded once in onCreate) ──────────────────────────
    private String cachedPublicKeyB64 = null;

    // =========================================================================
    // Lifecycle
    // =========================================================================

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildLayout());
        wireListeners();

        // Generate or retrieve the key pair on a background thread so we
        // never block the main thread on a potentially slow Keystore operation.
        executor.execute(this::initKeystore);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }

    // =========================================================================
    // Keystore — generate / retrieve
    // =========================================================================

    /**
     * Runs on the executor thread.
     * Creates an EC key pair inside the Android Keystore if one does not exist
     * yet, otherwise retrieves the existing entry.
     * The private key never leaves the Keystore; only the public key is read.
     */
    private void initKeystore() {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);

            // ── Generate if the alias is not yet present ──────────────────
            if (!ks.containsAlias(KEYSTORE_ALIAS)) {
                generateKeyPair();
            }

            // ── Extract public key ────────────────────────────────────────
            KeyStore.Entry entry = ks.getEntry(KEYSTORE_ALIAS, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                throw new KeyStoreException(
                        "Unexpected entry type for alias: " + KEYSTORE_ALIAS);
            }
            PublicKey publicKey =
                    ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();

            // DER-encoded SubjectPublicKeyInfo (X.509) → Base64 (no line wraps)
            cachedPublicKeyB64 = Base64.encodeToString(
                    publicKey.getEncoded(), Base64.NO_WRAP);

            // ── Check whether the key is hardware-backed ──────────────────
            PrivateKey privateKey =
                    ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            boolean isHardwareBacked = isKeyHardwareBacked(privateKey);

            String keySnippet = cachedPublicKeyB64.substring(0, 20) + "…";
            String label = isHardwareBacked
                    ? "🔒 Hardware-backed (TEE/StrongBox)"
                    : "⚠️  Software keystore (no secure HW)";

            mainHandler.post(() ->
                    tvKeyInfo.setText(label + "\nPublic: " + keySnippet));

        } catch (Exception e) {
            mainHandler.post(() ->
                    tvKeyInfo.setText("✗ Keystore error: " + e.getMessage()));
        }
    }

    /**
     * Creates an EC P-256 key pair inside the Android Keystore.
     *
     * KeyGenParameterSpec ensures:
     *  • The private key is bound to the Keystore and never exported.
     *  • Only SHA-256 digests are permitted for signing operations.
     *  • setInvalidatedByBiometricEnrollment(false) keeps the key alive if the
     *    user later changes their fingerprints. Set true for stricter security.
     *  • setUserAuthenticationRequired(false) means no biometric prompt is shown
     *    before signing. Set true + setUserAuthenticationValidityDurationSeconds
     *    if you want the OS to gate key use on biometric approval.
     */
    private void generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);

        kpg.initialize(
                new KeyGenParameterSpec.Builder(
                        KEYSTORE_ALIAS,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(false)
                        .setInvalidatedByBiometricEnrollment(false)
                        .build());

        kpg.generateKeyPair();
    }

    /**
     * Returns true when the private key material lives in secure hardware
     * (TEE or StrongBox) rather than in the OS software keystore.
     * Uses KeyInfo, available from API 23+.
     */
    private boolean isKeyHardwareBacked(PrivateKey privateKey) {
        try {
            KeyFactory factory = KeyFactory.getInstance(
                    privateKey.getAlgorithm(), ANDROID_KEYSTORE);
            KeyInfo info = factory.getKeySpec(privateKey, KeyInfo.class);
            return info.isInsideSecureHardware();
        } catch (Exception e) {
            return false; // cannot determine — assume software
        }
    }

    // =========================================================================
    // Networking
    // =========================================================================

    /**
     * POST { username, password, publicKey } to the given endpoint.
     * Runs on the executor thread; result posted back to the main thread.
     */
    private void callApi(String endpoint, String username, String password) {
        setLoading(true);

        executor.execute(() -> {
            // Guard: key must be ready before we can send it.
            if (cachedPublicKeyB64 == null) {
                mainHandler.post(() -> {
                    setLoading(false);
                    showStatus("✗ Key not ready yet — please wait a moment.", false);
                });
                return;
            }

            String  result;
            boolean success = false;

            try {
                URL url = new URL(SERVER_URL + endpoint);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);
                conn.setConnectTimeout(5_000);
                conn.setReadTimeout(5_000);

                // ── Build JSON body ───────────────────────────────────────
                String json = "{"
                        + "\"username\":\""  + escapeJson(username)           + "\","
                        + "\"password\":\""  + escapeJson(password)           + "\","
                        + "\"publicKey\":\"" + escapeJson(cachedPublicKeyB64) + "\""
                        + "}";

                byte[] body = json.getBytes(StandardCharsets.UTF_8);
                conn.setRequestProperty("Content-Length", String.valueOf(body.length));
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(body);
                }

                // ── Read response ─────────────────────────────────────────
                int         code = conn.getResponseCode();
                InputStream is   = (code < 400) ? conn.getInputStream()
                        : conn.getErrorStream();
                result = readStream(is);
                conn.disconnect();

                // ── Interpret server response ─────────────────────────────
                if (endpoint.equals("/login")) {
                    success = "accepted".equalsIgnoreCase(result);
                    result  = success ? "✓ Login successful!"
                            : "✗ Login rejected — check credentials.";
                } else { // /signup
                    success = "user created".equalsIgnoreCase(result);
                    result  = success ? "✓ Account created! You can now log in."
                            : "✗ Username already exists.";
                }

            } catch (IOException e) {
                result = "✗ Network error: " + e.getMessage()
                        + "\n\nCheck SERVER_URL and make sure the server is running.";
            }

            final String  msg = result;
            final boolean ok  = success;
            mainHandler.post(() -> {
                setLoading(false);
                showStatus(msg, ok);
            });
        });
    }

    // =========================================================================
    // Layout (programmatic — no XML required)
    // =========================================================================

    private View buildLayout() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(0xFF121212);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(32), dp(64), dp(32), dp(32));

        // ── Title ─────────────────────────────────────────────────────────
        TextView tvTitle = new TextView(this);
        tvTitle.setText("AuthClient");
        tvTitle.setTextSize(32);
        tvTitle.setTextColor(0xFFFFFFFF);
        tvTitle.setPadding(0, 0, 0, dp(4));
        root.addView(tvTitle);

        TextView tvSub = new TextView(this);
        tvSub.setText("Secure login with hardware key");
        tvSub.setTextSize(14);
        tvSub.setTextColor(0xFF9E9E9E);
        tvSub.setPadding(0, 0, 0, dp(16));
        root.addView(tvSub);

        // ── Key status badge ──────────────────────────────────────────────
        tvKeyInfo = new TextView(this);
        tvKeyInfo.setText("⏳ Initialising keystore…");
        tvKeyInfo.setTextSize(12);
        tvKeyInfo.setTextColor(0xFF80CBC4);
        tvKeyInfo.setBackgroundColor(0xFF1A2E2C);
        tvKeyInfo.setPadding(dp(12), dp(8), dp(12), dp(8));
        LinearLayout.LayoutParams kp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        kp.setMargins(0, 0, 0, dp(32));
        tvKeyInfo.setLayoutParams(kp);
        root.addView(tvKeyInfo);

        // ── Username ──────────────────────────────────────────────────────
        root.addView(makeLabel("Username"));
        etUsername = makeEditText("e.g. john_doe", false);
        root.addView(etUsername);

        // ── Password ──────────────────────────────────────────────────────
        root.addView(makeLabel("Password"));
        etPassword = makeEditText("••••••••", true);
        root.addView(etPassword);

        // ── Buttons ───────────────────────────────────────────────────────
        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);

        LinearLayout.LayoutParams bp1 = new LinearLayout.LayoutParams(0, dp(48), 1f);
        bp1.setMargins(0, dp(24), 0, 0);
        btnLogin = new Button(this);
        btnLogin.setText("Log In");
        btnLogin.setTextColor(0xFF000000);
        btnLogin.setBackgroundColor(0xFF4FC3F7);
        btnLogin.setLayoutParams(bp1);

        LinearLayout.LayoutParams bp2 = new LinearLayout.LayoutParams(0, dp(48), 1f);
        bp2.setMargins(dp(12), dp(24), 0, 0);
        btnSignup = new Button(this);
        btnSignup.setText("Sign Up");
        btnSignup.setTextColor(0xFFFFFFFF);
        btnSignup.setBackgroundColor(0xFF37474F);
        btnSignup.setLayoutParams(bp2);

        btnRow.addView(btnLogin);
        btnRow.addView(btnSignup);
        root.addView(btnRow);

        // ── Progress ──────────────────────────────────────────────────────
        progressBar = new ProgressBar(this);
        progressBar.setVisibility(View.GONE);
        LinearLayout.LayoutParams pp = new LinearLayout.LayoutParams(dp(40), dp(40));
        pp.setMargins(0, dp(24), 0, 0);
        progressBar.setLayoutParams(pp);
        root.addView(progressBar);

        // ── Status text ───────────────────────────────────────────────────
        tvStatus = new TextView(this);
        tvStatus.setTextSize(14);
        tvStatus.setTextColor(0xFF9E9E9E);
        tvStatus.setPadding(0, dp(24), 0, 0);
        root.addView(tvStatus);

        scroll.addView(root);
        return scroll;
    }

    // =========================================================================
    // Small helpers
    // =========================================================================

    private void wireListeners() {
        btnLogin.setOnClickListener(v -> {
            String user = etUsername.getText().toString().trim();
            String pass = etPassword.getText().toString().trim();
            if (validateInput(user, pass)) callApi("/login",  user, pass);
        });
        btnSignup.setOnClickListener(v -> {
            String user = etUsername.getText().toString().trim();
            String pass = etPassword.getText().toString().trim();
            if (validateInput(user, pass)) callApi("/signup", user, pass);
        });
    }

    private boolean validateInput(String user, String pass) {
        if (user.isEmpty()) { showStatus("Username cannot be empty.", false); return false; }
        if (pass.isEmpty()) { showStatus("Password cannot be empty.", false); return false; }
        return true;
    }

    private TextView makeLabel(String text) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextColor(0xFFB0BEC5);
        tv.setTextSize(12);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(16), 0, dp(4));
        tv.setLayoutParams(lp);
        return tv;
    }

    private EditText makeEditText(String hint, boolean isPassword) {
        EditText et = new EditText(this);
        et.setHint(hint);
        et.setHintTextColor(0xFF546E7A);
        et.setTextColor(0xFFFFFFFF);
        et.setBackgroundColor(0xFF1E1E1E);
        et.setPadding(dp(12), dp(12), dp(12), dp(12));
        if (isPassword) {
            et.setInputType(android.text.InputType.TYPE_CLASS_TEXT |
                    android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        }
        et.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(48)));
        return et;
    }

    private String readStream(InputStream is) throws IOException {
        if (is == null) return "(empty response)";
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(is, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        return sb.toString();
    }

    private String escapeJson(String v) {
        return v.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private void setLoading(boolean loading) {
        btnLogin.setEnabled(!loading);
        btnSignup.setEnabled(!loading);
        progressBar.setVisibility(loading ? View.VISIBLE : View.GONE);
        if (loading) tvStatus.setText("");
    }

    private void showStatus(String message, boolean success) {
        tvStatus.setText(message);
        tvStatus.setTextColor(success ? 0xFF81C784 : 0xFFEF9A9A);
    }

    private int dp(int dp) {
        return Math.round(dp * getResources().getDisplayMetrics().density);
    }
}