package com.fsck.k9.pqcExtension.keyManagement;

import java.util.Base64;
import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONException;
import org.json.JSONObject;
import org.openquantumsafe.KEMs;
import org.openquantumsafe.KeyEncapsulation;

public class PqcKemSimpleKeyManager {
    private static final String PREFS_NAME = "pqc_kem_keys";

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
        String json = getPrefs(context).getString(userId, null);
        if (json == null) throw new Exception("Kein Schlüssel gefunden");
        return new JSONObject(json);
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

    public static JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        JSONObject keyPair = loadKeyPair(context, userId);
        String algorithm = keyPair.getString("algorithm");
        String privateKey = keyPair.getString("privateKey");

        JSONObject keyJson = new JSONObject();
        keyJson.put("algorithm", algorithm);
        keyJson.put("privateKey", privateKey);
        return keyJson;
    }
}
