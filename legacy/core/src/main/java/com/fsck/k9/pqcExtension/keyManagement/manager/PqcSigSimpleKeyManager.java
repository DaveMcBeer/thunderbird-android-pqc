package com.fsck.k9.pqcExtension.keyManagement.manager;


import java.util.Base64;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONException;
import org.json.JSONObject;
import org.openquantumsafe.Signature;
import org.openquantumsafe.Sigs;


public class PqcSigSimpleKeyManager {
    private static final String PREFS_NAME = "pqc_sig_keys";
    private static final String REMOTE_PREFS = "pqc_sig_remote_keys";
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
            if (json == null || json.isEmpty()) return new JSONObject(); // statt Exception
            return new JSONObject(json);
        }
        else
            return new JSONObject();
    }

    public static void deleteKeyPair(Context context, String userId) {
        getPrefs(context).edit().remove(userId).apply();
    }
    public static void deleteAll(Context context) {
        getPrefs(context).edit().clear().apply();
    }
    public static boolean hasKeyPair(Context context, String userId) {
        return getPrefs(context).contains(userId);
    }
    public static JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        JSONObject keyPair = loadKeyPair(context, userId);
        if (!keyPair.has("algorithm") || !keyPair.has("privateKey")) {
            return null;
        }
        String algorithm = keyPair.getString("algorithm");
        String privateKey = keyPair.getString("privateKey");

        JSONObject keyJson = new JSONObject();
        keyJson.put("algorithm", algorithm);
        keyJson.put("privateKey", privateKey);
        return keyJson;
    }
    private static SharedPreferences getPrefs(Context context) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static void importRemotePublicKey(Context context, String remoteEmail, String algorithm, String publicKey) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(REMOTE_PREFS, Context.MODE_PRIVATE);
        JSONObject json = new JSONObject();
        json.put("algorithm", algorithm);
        json.put("publicKey", publicKey);

        prefs.edit().putString(remoteEmail.toLowerCase(), json.toString()).apply();
    }

    public static String exportPublicKey(Context context, String userId) throws Exception {
        JSONObject json = PqcSigSimpleKeyManager.loadKeyPair(context, userId);
        if(json.has("publicKey"))
            return json.getString("publicKey");
        else
            return "";
    }

    public static JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(REMOTE_PREFS, Context.MODE_PRIVATE);
        String json = prefs.getString(remoteEmail.toLowerCase(), null);
        if (json == null) return null;
        return new JSONObject(json);
    }
}

