package com.fsck.k9.pqcExtension.keyManagement.manager;

import java.util.Base64;
import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONException;
import org.json.JSONObject;
import org.openquantumsafe.KEMs;
import org.openquantumsafe.KeyEncapsulation;

public class PqcKemSimpleKeyManager {
    private static final String PREFS_NAME = "pqc_kem_keys";
    private static final String REMOTE_PREFS = "pqc_kem_remote_keys";
    public static void generateAndStoreKeyPair(Context context, String userId, String algorithm) {
        if (!KEMs.is_KEM_enabled(algorithm)) {
            throw new IllegalArgumentException("KEM-Algorithmus nicht unterstützt: " + algorithm);
        }

        KeyEncapsulation kem = new KeyEncapsulation(algorithm);
        try {
            kem.generate_keypair();
            String pub = Base64.getEncoder().encodeToString(kem.export_public_key());
            String priv = Base64.getEncoder().encodeToString(kem.export_secret_key());

            saveKeyPair(context, userId, algorithm, pub, priv);
        } finally {
            kem.dispose_KEM();
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
            if (json == null || json.isEmpty()) return new JSONObject();
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

    private static SharedPreferences getPrefs(Context context) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
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

    public static JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences("pqc_kem_remote_keys", Context.MODE_PRIVATE);
        String json = prefs.getString(remoteEmail.toLowerCase(), null);
        if (json == null) throw new Exception("Kein Remote-Key vorhanden");
        return new JSONObject(json);
    }

    public static String exportPublicKey(Context context, String userId) throws Exception {
        JSONObject json = PqcKemSimpleKeyManager.loadKeyPair(context, userId);
        if(json.has("publicKey"))
            return json.getString("publicKey");
        else
            return "";
    }

    public static void importRemotePublicKey(Context context, String ownerUserId, String remoteEmail, String algorithm, String publicKey) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(REMOTE_PREFS, Context.MODE_PRIVATE);
        JSONObject json = new JSONObject();
        json.put("algorithm", algorithm);
        json.put("publicKey", publicKey);
        prefs.edit().putString(remoteEmail.toLowerCase(), json.toString()).apply();
    }
}
