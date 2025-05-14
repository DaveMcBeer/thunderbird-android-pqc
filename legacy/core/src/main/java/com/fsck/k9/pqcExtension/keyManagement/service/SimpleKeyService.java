package com.fsck.k9.pqcExtension.keyManagement.service;


import android.content.Context;
import android.util.Log;

import com.fsck.k9.logging.Timber;
import com.fsck.k9.pqcExtension.keyManagement.PgpSimpleKeyStore;
import com.fsck.k9.pqcExtension.keyManagement.PqcKemSimpleKeyStore;
import com.fsck.k9.pqcExtension.keyManagement.PqcSigSimpleKeyStore;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStore;


public class SimpleKeyService {
    // Static instances of each key store (PGP, PQC Signature, PQC KEM)
    private static final SimpleKeyStore pgpStore = new PgpSimpleKeyStore();
    private static final SimpleKeyStore pqcSigStore = new PqcSigSimpleKeyStore();
    private static final SimpleKeyStore pqcKemStore = new PqcKemSimpleKeyStore();


    /**
     * Deletes all **local** key pairs for the specified user.
     * This includes PGP, PQC Signature, and PQC KEM keys.
     *
     * @param context   Android application context
     * @param accountId ID of the user/account
     */
    public static void ClearAllUsersKeys(Context context, String accountId) {
        try {
            pgpStore.clearAllKeys(context, accountId, true);
        } catch (Exception e) {
            Timber.e(e, "Failed to clear PGP keys for user: %s", accountId);
        }

        try {
            pqcSigStore.clearAllKeys(context, accountId, true);
        } catch (Exception e) {
            Timber.e(e, "Failed to clear PQC-SIG keys for user: %s", accountId);
        }

        try {
            pqcKemStore.clearAllKeys(context, accountId, true);
        } catch (Exception e) {
            Timber.e(e, "Failed to clear PQC-KEM keys for user: %s", accountId);
        }
    }


    /**
     * Ensures a PGP key pair exists for the user. If missing, it generates one.
     *
     * @param context      Android application context
     * @param accountId    ID of the user/account
     * @param pgpAlgorithm Algorithm name (currently not used but accepted)
     */
    public static void ensurePgpKeypairExists(Context context, String accountId, String pgpAlgorithm) {
        try {
            if (!pgpStore.hasOwnKeyPair(context, accountId)) {
                pgpStore.generateKeyPair(context, accountId, pgpAlgorithm);
            }
        } catch (Exception e) {
            Timber.e(e, "Failed to ensure PgpKeys exist for user: %s", accountId);
        }
    }
}

