package com.fsck.k9.pqcExtension.keyManagement;


import android.content.Context;

import org.json.JSONObject;


public interface SimpleKeyStore {
    void generateKeyPair(Context context, String userId, String algorithm) throws Exception;
    void importOwnKeyPair(Context context, String userId, String algorithm, String publicKey, String privateKey) throws Exception;
    void importRemotePublicKey(Context context, String ownerUserId, String remoteEmail, String algorithm, String publicKey) throws Exception;
    void clearAllKeys(Context context, String userId) throws Exception;

    String exportPublicKey(Context context, String userId) throws Exception;
    JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception;
    default String loadRemotePublicKeyArmoredString(Context context,String remoteEmail) throws Exception{
        JSONObject obj = loadRemotePublicKey(context, remoteEmail);
        return obj.getString("publicKey");  // Du kannst das gerne anpassen
    }
    boolean hasOwnKeyPair(Context context, String userId);
    JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception;

}

