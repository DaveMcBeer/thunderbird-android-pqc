// PqcKeyRegistry.java
package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;
import android.os.Build.VERSION_CODES;

import androidx.annotation.RequiresApi;
import org.json.JSONObject;

public
class PqcKeyRegistry implements IKeyRegistry {

    @RequiresApi(api = VERSION_CODES.O)
    @Override
    public void generateKeyPair(Context context, String id, String algorithm) throws Exception {
        String[] parts = algorithm.split("\\+");
        if (parts.length != 2) throw new IllegalArgumentException("Algorithmus-Format: 'kem+sig'");
        PqcKeyManager.generateKemKeyPair(id, parts[0]);
        PqcKeyManager.generateSigKeyPair(id, parts[1]);
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
    public String exportPublicKey(Context context,String id) throws Exception {
        if (!PqcKeyManager.hasKemKeyset(id) && !PqcKeyManager.hasSigKeyset(id)) {
            PqcKeyManager.loadKeysetFromStorage(null, id);
        }
        if (!PqcKeyManager.hasKemKeyset(id) && !PqcKeyManager.hasSigKeyset(id)) {
            throw new Exception("Kein PQC-Schlüssel verfügbar für ID: " + id);
        }
        return PqcKeyManager.exportPublicKeys(id);
    }

    @Override
    public void saveRemotePublicKey(Context context, String remoteEmail, String publicKeyJson) throws Exception {
        JSONObject json = new JSONObject(publicKeyJson);
        String sigAlg = json.optString("sigAlgorithm", null);
        String sigKey = json.optString("publicSigKey", null);
        String kemAlg = json.optString("kemAlgorithm", null);
        String kemKey = json.optString("publicKemKey", null);

        PqcKeyManager.saveRemotePublicKey(context, remoteEmail, sigAlg, sigKey, kemAlg, kemKey);
    }

    @Override
    public String loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        return PqcKeyManager.loadRemotePublicKey(context, remoteEmail).toString(2);
    }

    @Override
    public void clearKeyPair(Context context,String id) throws Exception {
        PqcKeyManager.deleteKeyset(context, id);
    }

    @Override
    public void setKeyPair(Context context, String id, String algorithm, String publicKey, String privateKey) throws Exception {
        PqcKeyManager.PqcKeyset keyset = new PqcKeyManager.PqcKeyset();
        keyset.sigAlgorithm = algorithm;
        keyset.publicSigKey = publicKey;
        keyset.privateSigKey = privateKey;

        // Zwischenspeichern
        PqcKeyManager.getKeyStore().put(id, keyset);

        // Persistieren
        PqcKeyManager.saveKeysetToStorage(context, id);
    }

    @Override
    public boolean hasKeyPair(Context context, String id) {
        try {
            PqcKeyManager.loadKeysetFromStorage(context, id);
            return PqcKeyManager.hasKemKeyset(id) && PqcKeyManager.hasSigKeyset(id);
        } catch (Exception e) {
            return false;
        }
    }
}
