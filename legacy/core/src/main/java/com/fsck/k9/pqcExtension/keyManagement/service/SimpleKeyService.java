package com.fsck.k9.pqcExtension.keyManagement.service;


import android.content.Context;

import com.fsck.k9.pqcExtension.keyManagement.PgpSimpleKeyStore;
import com.fsck.k9.pqcExtension.keyManagement.PqcKemSimpleKeyStore;
import com.fsck.k9.pqcExtension.keyManagement.PqcSigSimpleKeyStore;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStore;


public class SimpleKeyService {
    private static final SimpleKeyStore pgpStore = new PgpSimpleKeyStore();
    private static final SimpleKeyStore pqcSigStore = new PqcSigSimpleKeyStore();
    private static final SimpleKeyStore pqcKemStore = new PqcKemSimpleKeyStore();

    /**
     * Löscht alle **lokalen** Schlüssel (PGP, PQC-SIG, PQC-KEM) eines Users.
     *
     * @param context   Android Context
     * @param accountId Benutzer-ID
     */
    public static void ClearAllUsersKeys(Context context, String accountId) {
        try {
            pgpStore.clearAllKeys(context, accountId);
        } catch (Exception ignored) {}

        try {
            pqcSigStore.clearAllKeys(context, accountId);
        } catch (Exception ignored) {}

        try {
            pqcKemStore.clearAllKeys(context, accountId);
        } catch (Exception ignored) {}
    }

    public static void ensurePgpKeypairExists(Context context, String accountId, String pgpAlgorithm) {
        try {
            if (!pgpStore.hasOwnKeyPair(context, accountId)) {
                pgpStore.generateKeyPair(context, accountId, pgpAlgorithm);
            }
        } catch (Exception ignored) {}
    }
}

