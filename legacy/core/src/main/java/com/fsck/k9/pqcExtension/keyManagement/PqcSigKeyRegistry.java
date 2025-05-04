package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;
import android.os.Build.VERSION_CODES;

import androidx.annotation.RequiresApi;

import org.json.JSONObject;

public class PqcSigKeyRegistry implements IKeyRegistry {

    @RequiresApi(api = VERSION_CODES.O)
    @Override
    public void generateKeyPair(Context context, String id, String algorithm) throws Exception {
        PqcKeyManager.generateSigKeyPair(id, algorithm);
    }

    @Override
    public void saveOwnKeyPair(Context context, String id) throws Exception {
        PqcKeyManager.saveKeysetToStorage(context, id);
    }

    @Override
    public void loadOwnKeyPair(Context context, String id) throws Exception {
        PqcKeyManager.loadKeysetFromStorage(context, id);
    }

    @Override
    public String exportPublicKey(Context context, String id) throws Exception {
        if (!PqcKeyManager.hasSigKeyset(id)) {
            PqcKeyManager.loadKeysetFromStorage(context, id);
        }

        PqcKeyManager.PqcKeyset keyset = PqcKeyManager.getKeyset(id);
        if (keyset == null || keyset.publicSigKey == null) {
            throw new Exception("Kein Signatur-Schlüssel vorhanden für ID: " + id);
        }

        JSONObject json = new JSONObject();
        json.put("algorithm", keyset.sigAlgorithm);
        json.put("publicKey", keyset.publicSigKey);
        return json.toString(2);
    }

    @Override
    public void saveRemotePublicKey(Context context, String remoteEmail, String publicKeyJson) throws Exception {
        JSONObject json = new JSONObject(publicKeyJson);
        PqcKeyManager.saveRemotePublicKey(
            context,
            remoteEmail,
            json.getString("algorithm"),
            json.getString("publicKey"),
            null,
            null
        );
    }

    @Override
    public String loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        JSONObject json = PqcKeyManager.loadRemotePublicKey(context, remoteEmail);
        return new JSONObject()
            .put("algorithm", json.getString("sigAlgorithm"))
            .put("publicKey", json.getString("publicSigKey"))
            .toString(2);
    }

    @Override
    public void clearKeyPair(Context context, String id) throws Exception {
        PqcKeyManager.getKeyset(id).publicSigKey = null;
        PqcKeyManager.getKeyset(id).privateSigKey = null;
        PqcKeyManager.saveKeysetToStorage(context, id);
    }

    @Override
    public void setKeyPair(Context context, String id, String algorithm, String publicKey, String privateKey) throws Exception {
        PqcKeyManager.PqcKeyset keyset = PqcKeyManager.getKeyset(id);
        if (keyset == null) keyset = new PqcKeyManager.PqcKeyset();
        keyset.sigAlgorithm = algorithm;
        keyset.publicSigKey = publicKey;
        keyset.privateSigKey = privateKey;
        PqcKeyManager.getKeyStore().put(id, keyset);
        PqcKeyManager.saveKeysetToStorage(context, id);
    }

    @Override
    public boolean hasKeyPair(Context context, String id) {
        try {
            PqcKeyManager.loadKeysetFromStorage(context, id);
            return PqcKeyManager.hasSigKeyset(id);
        } catch (Exception e) {
            return false;
        }
    }
}
