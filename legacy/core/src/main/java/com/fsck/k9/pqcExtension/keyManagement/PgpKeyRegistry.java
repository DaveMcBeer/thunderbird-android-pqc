package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;
import android.os.Build.VERSION_CODES;

import androidx.annotation.RequiresApi;

import java.security.KeyPair;

public class PgpKeyRegistry implements IKeyRegistry {

    @RequiresApi(api = VERSION_CODES.O)
    @Override
    public void generateKeyPair(Context context, String id, String algorithm) throws Exception {
        PgpKeyManager.generateAndStoreKeyPair(context, id);
    }

    @Override
    public void saveOwnKeyPair(Context context, String id) {
        // Bereits in generateAndStore enthalten
    }

    @RequiresApi(api = VERSION_CODES.O)
    @Override
    public void loadOwnKeyPair(Context context, String id) throws Exception {
        PgpKeyManager.loadKeyPairCached(context, id);
    }

    @RequiresApi(api = VERSION_CODES.O)
    @Override
    public String exportPublicKey(Context context,String id) throws Exception {
        KeyPair pair = PgpKeyManager.keyStore.get(id);
        if (pair == null) {
            pair = PgpKeyManager.loadKeyPairCached(context, id);
        }
        if (pair == null) {
            throw new Exception("Kein KeyPair verfügbar für ID: " + id + ".");
        }
        return PgpKeyManager.exportPublicKeyArmored(pair.getPublic());
    }

    @RequiresApi(api = VERSION_CODES.O)
    @Override
    public void saveRemotePublicKey(Context context, String remoteEmail, String publicKey) throws Exception {
        PgpKeyManager.saveRemotePublicKey(context, remoteEmail, publicKey);
    }

    @RequiresApi(api = VERSION_CODES.O)
    @Override
    public String loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        return PgpKeyManager.loadRemotePublicKey(context, remoteEmail);
    }

    @Override
    public void clearKeyPair(Context context,String id) throws Exception {
        PgpKeyManager.deleteKeySet(context, id);
    }

    @RequiresApi(api = VERSION_CODES.O)
    @Override
    public void setKeyPair(Context context, String id, String algorithm, String publicKey, String privateKey) throws Exception {
        PgpKeyManager.setKeyPair(context, id, publicKey, privateKey);
    }

    @Override
    public boolean hasKeyPair(Context context, String id) {
        try {
            PgpKeyManager.loadKeyPairCached(context, id);
            return PgpKeyManager.hasKeyset(id);
        } catch (Exception e) {
            return false;
        }
    }
}

