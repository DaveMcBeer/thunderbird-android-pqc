package com.fsck.k9.pqcExtension.keyManagement.manager;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import org.json.JSONException;
import org.json.JSONObject;
import org.openquantumsafe.Signature;
import org.openquantumsafe.Sigs;

import java.util.Base64;

public class PqcSigSimpleKeyManager {
    private static final String PREFS_NAME = "pqc_sig_keys_secure";
    private static final String REMOTE_PREFS = "pqc_sig_remote_keys";

    /**
     * Returns encrypted SharedPreferences to securely store local key data.
     */
    private static SharedPreferences getEncryptedPrefs(Context context) throws Exception {
        MasterKey masterKey = new MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();

        return EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }

    /**
     * Generates a new post-quantum signature key pair and stores it securely.
     */
    public static void generateAndStoreKeyPair(Context context, String userId, String algorithm) {
        if (!Sigs.is_sig_enabled(algorithm)) {
            throw new IllegalArgumentException("Signature algorithm not supported: " + algorithm);
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

    /**
     * Saves a local key pair with metadata (algorithm, base64 public/private keys).
     */
    public static void saveKeyPair(Context context, String userId, String algorithm, String publicKey, String privateKey) {
        try {
            JSONObject json = new JSONObject();
            json.put("algorithm", algorithm);
            json.put("publicKey", publicKey);
            json.put("privateKey", privateKey);
            getEncryptedPrefs(context).edit().putString(userId, json.toString()).apply();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Loads a complete key pair (if available) as a JSONObject.
     */
    public static JSONObject loadKeyPair(Context context, String userId) throws Exception {
        SharedPreferences prefs = getEncryptedPrefs(context);
        if (prefs.contains(userId)) {
            String json = prefs.getString(userId, null);
            if (json == null || json.isEmpty()) return new JSONObject();
            return new JSONObject(json);
        } else {
            return new JSONObject();
        }
    }

    /**
     * Deletes a user's key pair from secure storage.
     */
    public static void deleteKeyPair(Context context, String userId) throws Exception {
        getEncryptedPrefs(context).edit().remove(userId).apply();
    }


    /**
     * Clears all locally stored signature keys.
     */
    public static void deleteAll(Context context) throws Exception {
        getEncryptedPrefs(context).edit().clear().apply();
    }

    /**
     * Checks if a key pair exists for a specific user.
     */
    public static boolean hasKeyPair(Context context, String userId) throws Exception {
        return getEncryptedPrefs(context).contains(userId);
    }

    /**
     * Loads only the local private key and algorithm for signing operations.
     */
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

    /**
     * Stores a remote contact's public signature key.
     */
    public static void importRemotePublicKey(Context context, String remoteEmail, String algorithm, String publicKey) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(REMOTE_PREFS, Context.MODE_PRIVATE);
        JSONObject json = new JSONObject();
        json.put("algorithm", algorithm);
        json.put("publicKey", publicKey);
        prefs.edit().putString(remoteEmail.toLowerCase(), json.toString()).apply();
    }

    /**
     * Exports the public key of a local user (if available).
     */
    public static String exportPublicKey(Context context, String userId) throws Exception {
        JSONObject json = loadKeyPair(context, userId);
        if (json.has("publicKey"))
            return json.getString("publicKey");
        else
            return "";
    }


    /**
     * Loads a public key for a given remote contact.
     */
    public static JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(REMOTE_PREFS, Context.MODE_PRIVATE);
        String json = prefs.getString(remoteEmail.toLowerCase(), null);
        if (json == null) return null;
        return new JSONObject(json);
    }
}
