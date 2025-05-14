package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;

import com.fsck.k9.pqcExtension.keyManagement.manager.PgpSimpleKeyManager;
import org.bouncycastle.openpgp.PGPException;
import org.json.JSONObject;

import java.io.IOException;

public class PgpSimpleKeyStore implements SimpleKeyStore {

    @Override
    public void generateKeyPair(Context context, String userId, String algorithm) throws Exception {
        try {
            PgpSimpleKeyManager.generateAndStoreKeyPair(context, userId);
        } catch (Exception e) {
            throw new Exception("Fehler beim Generieren des PGP-Schlüsselpaares", e);
        }
    }

    @Override
    public void importOwnKeyPair(Context context, String userId, String algorithm, String publicKey, String privateKey) throws Exception {
        try {
            PgpSimpleKeyManager.importArmoredKeyPair(context, userId, publicKey, privateKey);
        } catch (Exception e) {
            throw new Exception("Fehler beim Importieren des eigenen PGP-Schlüsselpaares", e);
        }
    }

    @Override
    public void importRemotePublicKey(Context context, String ownerUserId, String remoteEmail, String algorithm, String publicKey) throws Exception {
        try {
            PgpSimpleKeyManager.saveRemotePublicKey(context, ownerUserId, remoteEmail, algorithm, publicKey);
        } catch (Exception e) {
            throw new Exception("Fehler beim Importieren des Remote-PGP-Schlüssels", e);
        }
    }

    @Override
    public void clearAllKeys(Context context, String userId, Boolean deleteRemote) {
        try {
            PgpSimpleKeyManager.deleteAll(context);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public String exportPublicKey(Context context, String userId) throws IOException, PGPException {
        try {
            return PgpSimpleKeyManager.exportArmoredPublicKey(context, userId);
        } catch (Exception e) {
            throw new RuntimeException("Fehler beim Exportieren des PGP-Keys", e);
        }
    }

    @Override
    public JSONObject loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        try {
            String armored = PgpSimpleKeyManager.loadRemotePublicKey(context, remoteEmail);
            JSONObject obj = new JSONObject();
            obj.put("algorithm", "PGP");
            obj.put("publicKey", armored);
            return obj;
        } catch (Exception e) {
            throw new Exception("Fehler beim Laden des Remote-PGP-Schlüssels", e);
        }
    }

    public String loadRemotePublicKeyArmoredString(Context context, String remoteEmail) throws Exception {
        try {
            return PgpSimpleKeyManager.loadRemotePublicKey(context, remoteEmail);
        } catch (Exception e) {
            throw new Exception("Fehler beim Laden des Remote-PGP-Keys (armored)", e);
        }
    }

    @Override
    public boolean hasOwnKeyPair(Context context, String userId) {
        try {
            return PgpSimpleKeyManager.hasKeyPair(context, userId);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        try {
            return PgpSimpleKeyManager.loadLocalPrivateKey(context, userId);
        } catch (Exception e) {
            throw new Exception("Fehler beim Laden des lokalen privaten PGP-Schlüssels", e);
        }
    }
}
