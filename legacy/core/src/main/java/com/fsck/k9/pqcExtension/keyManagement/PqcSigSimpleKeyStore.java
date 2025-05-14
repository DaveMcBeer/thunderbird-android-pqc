package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;
import com.fsck.k9.pqcExtension.keyManagement.manager.PqcSigSimpleKeyManager;
import org.json.JSONObject;

public class PqcSigSimpleKeyStore implements SimpleKeyStore {

    @Override
    public void generateKeyPair(Context context, String userId, String algorithm) throws Exception {
        try {
            PqcSigSimpleKeyManager.generateAndStoreKeyPair(context, userId, algorithm);
        } catch (Exception e) {
            throw new Exception("Failed to generate PQC signature key pair", e);
        }
    }

    @Override
    public void importOwnKeyPair(Context context, String userId, String algorithm, String publicKey, String privateKey) throws Exception {
        try {
            PqcSigSimpleKeyManager.saveKeyPair(context, userId, algorithm, publicKey, privateKey);
        } catch (Exception e) {
            throw new Exception("Failed to import own PQC signature key pair", e);
        }
    }

    @Override
    public void importRemotePublicKey(Context context, String ownerUserId, String remoteEmail, String algorithm, String publicKey) throws Exception {
        try {
            PqcSigSimpleKeyManager.importRemotePublicKey(context, remoteEmail, algorithm, publicKey);
        } catch (Exception e) {
            throw new Exception("Failed to import remote PQC signature public key", e);
        }
    }

    @Override
    public void clearAllKeys(Context context, String userId, Boolean deleteAll) throws Exception {
        try {
            if (deleteAll) {
                PqcSigSimpleKeyManager.deleteAll(context);
            } else {
                PqcSigSimpleKeyManager.deleteKeyPair(context, userId);
            }
        } catch (Exception e) {
            throw new Exception("Failed to delete PQC signature keys", e);
        }
    }

    @Override
    public String exportPublicKey(Context context, String userId) throws Exception {
        try {
            return PqcSigSimpleKeyManager.exportPublicKey(context, userId);
        } catch (Exception e) {
            throw new Exception("Failed to export PQC signature public key", e);
        }
    }

    @Override
    public JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        try {
            return PqcSigSimpleKeyManager.loadRemotePublicKey(context, remoteEmail);
        } catch (Exception e) {
            throw new Exception("Failed to load remote PQC signature public key", e);
        }
    }

    @Override
    public boolean hasOwnKeyPair(Context context, String userId) {
        try {
            return PqcSigSimpleKeyManager.hasKeyPair(context, userId);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        try {
            return PqcSigSimpleKeyManager.loadLocalPrivateKey(context, userId);
        } catch (Exception e) {
            throw new Exception("Failed to load local PQC signature private key", e);
        }
    }
}
