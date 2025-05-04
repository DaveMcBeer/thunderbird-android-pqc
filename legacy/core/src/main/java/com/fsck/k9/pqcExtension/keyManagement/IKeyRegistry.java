package com.fsck.k9.pqcExtension.keyManagement;


import android.content.Context;

import org.json.JSONObject;


public interface IKeyRegistry{
    void generateKeyPair(Context context, String id, String algorithm) throws Exception;
    void saveOwnKeyPair(Context context, String id) throws Exception;
    void loadOwnKeyPair(Context context, String id) throws Exception;
    String exportPublicKey(Context context,String id) throws Exception;

    void saveRemotePublicKey(Context context, String remoteEmail, String publicKey) throws Exception;
    default void saveRemotePublicKey(Context context, String remoteEmail, String sigAlg, String sigKey, String kemAlg, String kemKey) throws Exception {
        JSONObject json = new JSONObject();
        if (sigAlg != null && sigKey != null) {
            json.put("sigAlgorithm", sigAlg);
            json.put("publicSigKey", sigKey);
        }
        if (kemAlg != null && kemKey != null) {
            json.put("kemAlgorithm", kemAlg);
            json.put("publicKemKey", kemKey);
        }
        if (json.length() > 0) {
            saveRemotePublicKey(context, remoteEmail, json.toString());
        }
    }
    String loadRemotePublicKey(Context context, String remoteEmail) throws Exception;

    void clearKeyPair(Context context,String id) throws Exception;
    void setKeyPair(Context context, String id, String algorithm, String publicKey, String privateKey) throws Exception;
    boolean hasKeyPair(Context context, String id);
}
