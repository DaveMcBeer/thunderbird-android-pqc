package com.fsck.k9.pqcExtension;


import android.content.Context;
import android.os.Build;

import androidx.annotation.RequiresApi;
import com.fsck.k9.pqcExtension.keyManagement.IKeyRegistry;
import com.fsck.k9.pqcExtension.keyManagement.KeyRegistryFactory;
import com.fsck.k9.pqcExtension.keyManagement.KeyRegistryFactory.KeyType;
import com.fsck.k9.pqcExtension.keyManagement.PgpKeyManager;


public class PqcExtensionCore{

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void ensurePgpKeypairExists(Context context, String accountId) throws Exception {
        if (PgpKeyManager.loadKeyPair(context, accountId) == null) {
            PgpKeyManager.generateAndStoreKeyPair(context, accountId);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void generatePqcSigningKeypair(Context context, String accountId, String algorithm) throws Exception {
        ensurePgpKeypairExists(context, accountId);
        IKeyRegistry pqcRegistry = KeyRegistryFactory.getRegistry(KeyType.PQC_SIG);
        pqcRegistry.generateKeyPair(context, accountId, algorithm); //
        pqcRegistry.saveOwnKeyPair(context, accountId);
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void generatePqcKemKeypair(Context context, String accountId, String algorithm) throws Exception {
        ensurePgpKeypairExists(context, accountId);
        IKeyRegistry pqcRegistry = KeyRegistryFactory.getRegistry(KeyType.PQC_KEM);
        pqcRegistry.generateKeyPair(context, accountId, algorithm);
        pqcRegistry.saveOwnKeyPair(context, accountId);
    }

}
