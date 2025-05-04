package com.fsck.k9.pqcExtension.keyManagement;


import android.content.Context;
import android.os.Build;

import androidx.annotation.RequiresApi;


public class KeyResetHelper {
    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void deleteAllKeysForAccount(Context context, String accountId) {
        context.getSharedPreferences("secure_pgp_keys", Context.MODE_PRIVATE).edit().remove(accountId + "_pub").remove(accountId + "_priv").apply();
        context.getSharedPreferences("pgp_remote_pubkeys", Context.MODE_PRIVATE).edit().remove(accountId.toLowerCase()).apply();
        context.getSharedPreferences("pqc_secure_keys", Context.MODE_PRIVATE).edit().remove(accountId).apply();
        context.getSharedPreferences("pqc_remote_pubkeys", Context.MODE_PRIVATE).edit().remove(accountId.toLowerCase()).apply();
    }
}

