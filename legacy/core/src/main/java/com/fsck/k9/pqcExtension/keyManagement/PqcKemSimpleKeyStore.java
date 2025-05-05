package com.fsck.k9.pqcExtension.keyManagement;


import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;


public class PqcKemSimpleKeyStore implements SimpleKeyStore {

    @Override
    public void generateKeyPair(Context context, String userId, String algorithm) throws Exception {
        PqcKemSimpleKeyManager.generateAndStoreKeyPair(context, userId, algorithm);
    }

    @Override
    public void importOwnKeyPair(Context context, String userId, String algorithm, String publicKey, String privateKey) throws Exception {
        PqcKemSimpleKeyManager.saveKeyPair(context, userId, algorithm, publicKey, privateKey);
    }

    @Override
    public void importRemotePublicKey(Context context, String ownerUserId, String remoteEmail, String algorithm, String publicKey) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences("pqc_kem_remote_keys", Context.MODE_PRIVATE);
        JSONObject json = new JSONObject();
        json.put("algorithm", algorithm);
        json.put("publicKey", publicKey);
        prefs.edit().putString(remoteEmail.toLowerCase(), json.toString()).apply();
    }

    @Override
    public void clearAllKeys(Context context, String userId) throws Exception {
        PqcKemSimpleKeyManager.deleteKeyPair(context, userId);
    }

    @Override
    public String exportPublicKey(Context context, String userId) throws Exception {
        JSONObject json = PqcKemSimpleKeyManager.loadKeyPair(context, userId);
        return json.getString("publicKey");
    }

    @Override
    public JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences("pqc_kem_remote_keys", Context.MODE_PRIVATE);
        String json = prefs.getString(remoteEmail.toLowerCase(), null);
        if (json == null) throw new Exception("Kein Remote-Key vorhanden");
        return new JSONObject(json);
    }

    @Override
    public boolean hasOwnKeyPair(Context context, String userId) {
        return PqcKemSimpleKeyManager.hasKeyPair(context, userId);
    }
}
