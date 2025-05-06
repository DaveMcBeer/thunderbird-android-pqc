package com.fsck.k9.pqcExtension.keyManagement;


import android.content.Context;
import android.content.SharedPreferences;

import com.fsck.k9.pqcExtension.keyManagement.manager.PgpSimpleKeyManager;
import com.fsck.k9.pqcExtension.keyManagement.manager.PqcSigSimpleKeyManager;
import org.json.JSONObject;


public class PqcSigSimpleKeyStore implements SimpleKeyStore {

    @Override
    public void generateKeyPair(Context context, String userId, String algorithm) throws Exception {
        PqcSigSimpleKeyManager.generateAndStoreKeyPair(context, userId, algorithm);
    }

    @Override
    public void importOwnKeyPair(Context context, String userId, String algorithm, String publicKey, String privateKey) throws Exception {
        PqcSigSimpleKeyManager.saveKeyPair(context, userId, algorithm, publicKey, privateKey);
    }

    @Override
    public void importRemotePublicKey(Context context, String ownerUserId, String remoteEmail, String algorithm, String publicKey) throws Exception {
        PqcSigSimpleKeyManager.importRemotePublicKey(context,remoteEmail,algorithm,publicKey);
    }

    @Override
    public void clearAllKeys(Context context, String userId,Boolean deleteAll) throws Exception {
        if(deleteAll)
            PqcSigSimpleKeyManager.deleteAll(context);
        else
            PqcSigSimpleKeyManager.deleteKeyPair(context, userId);
    }

    @Override
    public String exportPublicKey(Context context, String userId) throws Exception {
        return PqcSigSimpleKeyManager.exportPublicKey(context,userId);
    }

    @Override
    public JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        return PqcSigSimpleKeyManager.loadRemotePublicKey(context,remoteEmail);
    }

    @Override
    public boolean hasOwnKeyPair(Context context, String userId) {
        return PqcSigSimpleKeyManager.hasKeyPair(context, userId);
    }

    @Override
    public JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        return PqcSigSimpleKeyManager.loadLocalPrivateKey(context, userId);
    }
}
