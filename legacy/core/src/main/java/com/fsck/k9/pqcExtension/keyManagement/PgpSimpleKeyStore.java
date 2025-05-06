package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;
import org.bouncycastle.openpgp.PGPException;
import org.json.JSONObject;

import java.io.IOException;

public class PgpSimpleKeyStore implements SimpleKeyStore {

    @Override
    public void generateKeyPair(Context context, String userId, String algorithm) throws Exception {
        // Algorithm wird ignoriert, da Ed25519 festgelegt ist
        PgpSimpleKeyManager.generateAndStoreKeyPair(context, userId);
    }

    @Override
    public void importOwnKeyPair(Context context, String userId, String algorithm, String publicKey, String privateKey) throws Exception {
        PgpSimpleKeyManager.importArmoredKeyPair(context, userId, publicKey, privateKey);
    }

    @Override
    public void importRemotePublicKey(Context context, String ownerUserId, String remoteEmail, String algorithm, String publicKey) throws Exception {
        PgpSimpleKeyManager.saveRemotePublicKey(context, ownerUserId, remoteEmail, algorithm, publicKey);
    }

    @Override
    public void clearAllKeys(Context context, String userId) {
        PgpSimpleKeyManager.deleteKeyPair(context, userId);
    }

    @Override
    public String exportPublicKey(Context context, String userId) throws IOException, PGPException {
        try {
            return PgpSimpleKeyManager.exportArmoredPublicKey(context, userId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        return null;
    }

    public String loadRemotePublicKeyArmoredString(Context context, String remoteEmail) throws Exception {
        return PgpSimpleKeyManager.loadRemotePublicKey(context, remoteEmail);
    }

    @Override
    public boolean hasOwnKeyPair(Context context, String userId) {
        return PgpSimpleKeyManager.hasKeyPair(context, userId);
    }

    @Override
    public JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        return PgpSimpleKeyManager.loadLocalPrivateKey(context, userId);
    }

}
