package com.fsck.k9.pqcExtension.keyManagement;


import android.content.Context;
import android.content.SharedPreferences;

import com.fsck.k9.pqcExtension.keyManagement.manager.PqcKemSimpleKeyManager;
import com.fsck.k9.pqcExtension.keyManagement.manager.PqcSigSimpleKeyManager;
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
        PqcKemSimpleKeyManager.importRemotePublicKey(context,ownerUserId,remoteEmail,algorithm,publicKey);
    }

    @Override
    public void clearAllKeys(Context context, String userId,Boolean deleteAll) throws Exception {
        if(deleteAll)
            PqcKemSimpleKeyManager.deleteAll(context);
        else
            PqcKemSimpleKeyManager.deleteKeyPair(context, userId);
    }
    @Override
    public String exportPublicKey(Context context, String userId) throws Exception {
        return PqcKemSimpleKeyManager.exportPublicKey(context,userId);
    }

    @Override
    public JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        return PqcKemSimpleKeyManager.loadRemotePublicKey(context,remoteEmail);
    }

    @Override
    public boolean hasOwnKeyPair(Context context, String userId) {
        return PqcKemSimpleKeyManager.hasKeyPair(context, userId);
    }

    @Override
    public JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        return PqcKemSimpleKeyManager.loadLocalPrivateKey(context, userId);
    }
}
