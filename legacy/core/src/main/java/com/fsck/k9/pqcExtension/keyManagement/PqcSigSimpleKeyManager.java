package com.fsck.k9.pqcExtension.keyManagement;


import java.util.Base64;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONException;
import org.json.JSONObject;
import org.openquantumsafe.Signature;
import org.openquantumsafe.Sigs;


public class PqcSigSimpleKeyManager {
    private static final String PREFS_NAME = "pqc_sig_keys";

    public static void generateAndStoreKeyPair(Context context, String userId, String algorithm) {
        if (!Sigs.is_sig_enabled(algorithm)) {
            throw new IllegalArgumentException("Algorithmus nicht unterstützt: " + algorithm);
        }

        Signature sig = new Signature(algorithm);
        try {
            sig.generate_keypair();
            String pub = Base64.getEncoder().encodeToString(sig.export_public_key());
            String priv = Base64.getEncoder().encodeToString(sig.export_secret_key());

            saveKeyPair(context, userId, algorithm, pub, priv);
        } finally {
            sig.dispose_sig();
        }
    }

    public static void saveKeyPair(Context context, String userId, String algorithm, String publicKey, String privateKey) {
        try {
            JSONObject json = new JSONObject();
            json.put("algorithm", algorithm);
            json.put("publicKey", publicKey);
            json.put("privateKey", privateKey);
            getPrefs(context).edit().putString(userId, json.toString()).apply();
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
    }

    public static JSONObject loadKeyPair(Context context, String userId) throws Exception {
        if(hasKeyPair(context, userId)){
            String json = getPrefs(context).getString(userId, null);
            if (json == null) throw new Exception("Kein Schlüssel gefunden");
            return new JSONObject(json);
        }
        else
            return new JSONObject();
    }

    public static void deleteKeyPair(Context context, String userId) {
        getPrefs(context).edit().remove(userId).apply();
    }

    public static boolean hasKeyPair(Context context, String userId) {
        return getPrefs(context).contains(userId);
    }

    private static SharedPreferences getPrefs(Context context) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }
}

