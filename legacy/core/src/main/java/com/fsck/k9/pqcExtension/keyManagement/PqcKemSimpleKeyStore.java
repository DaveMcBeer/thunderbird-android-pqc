package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;
import com.fsck.k9.pqcExtension.keyManagement.manager.PqcKemSimpleKeyManager;
import org.json.JSONObject;

public class PqcKemSimpleKeyStore implements SimpleKeyStore {

    @Override
    public void generateKeyPair(Context context, String userId, String algorithm) throws Exception {
        try {
            PqcKemSimpleKeyManager.generateAndStoreKeyPair(context, userId, algorithm);
        } catch (Exception e) {
            throw new Exception("Failed to generate PQC-KEM key pair", e);
        }
    }

    @Override
    public void importOwnKeyPair(Context context, String userId, String algorithm, String publicKey, String privateKey) throws Exception {
        try {
            PqcKemSimpleKeyManager.saveKeyPair(context, userId, algorithm, publicKey, privateKey);
        } catch (Exception e) {
            throw new Exception("Failed to import own PQC-KEM key pair", e);
        }
    }

    @Override
    public void importRemotePublicKey(Context context, String ownerUserId, String remoteEmail, String algorithm, String publicKey) throws Exception {
        try {
            PqcKemSimpleKeyManager.importRemotePublicKey(context, ownerUserId, remoteEmail, algorithm, publicKey);
        } catch (Exception e) {
            throw new Exception("Failed to import remote KEM public key", e);
        }
    }

    @Override
    public void clearAllKeys(Context context, String userId, Boolean deleteAll) throws Exception {
        try {
            if (deleteAll) {
                PqcKemSimpleKeyManager.deleteAll(context);
            } else {
                PqcKemSimpleKeyManager.deleteKeyPair(context, userId);
            }
        } catch (Exception e) {
            throw new Exception("Failed to delete PQC-KEM keys", e);
        }
    }

    @Override
    public String exportPublicKey(Context context, String userId) throws Exception {
        try {
            return PqcKemSimpleKeyManager.exportPublicKey(context, userId);
        } catch (Exception e) {
            throw new Exception("Failed to export PQC-KEM public key", e);
        }
    }

    @Override
    public JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        try {
            return PqcKemSimpleKeyManager.loadRemotePublicKey(context, remoteEmail);
        } catch (Exception e) {
            throw new Exception("Failed to load remote KEM public key", e);
        }
    }

    @Override
    public boolean hasOwnKeyPair(Context context, String userId) {
        try {
            return PqcKemSimpleKeyManager.hasKeyPair(context, userId);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        try {
            return PqcKemSimpleKeyManager.loadLocalPrivateKey(context, userId);
        } catch (Exception e) {
            throw new Exception("Failed to load local PQC-KEM private key", e);
        }
    }
}
