package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Build.VERSION_CODES;

import androidx.annotation.RequiresApi;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;
import org.json.JSONObject;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.KEMs;
import org.openquantumsafe.Signature;
import org.openquantumsafe.Sigs;

import java.util.HashMap;
import java.util.Map;
import java.util.Base64;
public class PqcKeyManager{

    private static final Map<String, PqcKeyset> keyStore = new HashMap<>();

    public static class PqcKeyset {
        public String sigAlgorithm;
        public String kemAlgorithm;

        public String publicSigKey;
        public String privateSigKey;

        public String publicKemKey;
        public String privateKemKey;
    }

    /** Erzeugt und speichert ein Signatur-Schlüsselpaar */
    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void generateSigKeyPair(String accountId, String algorithm) {
        if (!Sigs.is_sig_enabled(algorithm)) {
            throw new IllegalArgumentException("Signaturalgorithmus nicht unterstützt: " + algorithm);
        }

        Signature sig = new Signature(algorithm);
        try {
            sig.generate_keypair();
            PqcKeyset keyset = getOrCreateKeyset(accountId);
            keyset.sigAlgorithm = algorithm;
            keyset.publicSigKey = Base64.getMimeEncoder().encodeToString(sig.export_public_key());
            keyset.privateSigKey = Base64.getMimeEncoder().encodeToString(sig.export_secret_key());
        } finally {
            sig.dispose_sig();
        }
    }

    /** Erzeugt und speichert ein KEM-Schlüsselpaar */
    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void generateKemKeyPair(String accountId, String algorithm) {
        if (!KEMs.is_KEM_enabled(algorithm)) {
            throw new IllegalArgumentException("KEM-Algorithmus nicht unterstützt: " + algorithm);
        }

        KeyEncapsulation kem = new KeyEncapsulation(algorithm);
        try {
            kem.generate_keypair();
            PqcKeyset keyset = getOrCreateKeyset(accountId);
            keyset.kemAlgorithm = algorithm;
            keyset.publicKemKey = Base64.getMimeEncoder().encodeToString(kem.export_public_key());
            keyset.privateKemKey = Base64.getMimeEncoder().encodeToString(kem.export_secret_key());
        } finally {
            kem.dispose_KEM();
        }
    }

    /** Exportiert die öffentlichen Schlüssel für einen Account als JSON */
    public static String exportPublicKeys(String accountId) throws Exception {
        PqcKeyset keyset = keyStore.get(accountId);
        if (keyset == null) throw new Exception("Keine Schlüssel für Account: " + accountId);

        JSONObject json = new JSONObject();
        json.put("accountId", accountId);
        json.put("sigAlgorithm", keyset.sigAlgorithm);
        json.put("kemAlgorithm", keyset.kemAlgorithm);
        json.put("publicSigKey", keyset.publicSigKey);
        json.put("publicKemKey", keyset.publicKemKey);

        return json.toString(2); // formatiert
    }

    /** Interner Helfer zur Initialisierung eines Account-Keysets */
    private static PqcKeyset getOrCreateKeyset(String accountId) {
        if (!keyStore.containsKey(accountId)) {
            keyStore.put(accountId, new PqcKeyset());
        }
        return keyStore.get(accountId);
    }

    public static PqcKeyset getKeyset(String accountId) {
        return keyStore.get(accountId);
    }

    public static boolean hasKemKeyset(String accountId) {
        PqcKeyset keyset = keyStore.get(accountId);
        return keyset != null &&
            keyset.publicKemKey != null &&
            keyset.privateKemKey != null;
    }

    public static boolean hasSigKeyset(String accountId) {
        PqcKeyset keyset = keyStore.get(accountId);
        return keyset != null &&
            keyset.publicSigKey != null &&
            keyset.privateSigKey != null;
    }
    @RequiresApi(api = VERSION_CODES.GINGERBREAD)
    public static void saveKeysetToStorage(Context context, String accountId) throws Exception {
        PqcKeyset keyset = keyStore.get(accountId);
        if (keyset == null) throw new Exception("Kein Schlüssel zum Speichern für Account: " + accountId);

        SharedPreferences prefs = EncryptedSharedPreferences.create(
            "pqc_secure_keys",
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        JSONObject json = new JSONObject();
        json.put("sigAlgorithm", keyset.sigAlgorithm);
        json.put("kemAlgorithm", keyset.kemAlgorithm);
        json.put("publicSigKey", keyset.publicSigKey);
        json.put("privateSigKey", keyset.privateSigKey);
        json.put("publicKemKey", keyset.publicKemKey);
        json.put("privateKemKey", keyset.privateKemKey);

        prefs.edit().putString(accountId, json.toString()).apply();
    }

    public static void loadKeysetFromStorage(Context context, String accountId) throws Exception {
        SharedPreferences prefs = EncryptedSharedPreferences.create(
            "pqc_secure_keys",
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        String jsonString = prefs.getString(accountId, null);
        if (jsonString == null) throw new Exception("Kein gespeicherter Schlüssel gefunden für Account: " + accountId);

        JSONObject json = new JSONObject(jsonString);
        PqcKeyset keyset = new PqcKeyset();
        keyset.sigAlgorithm = json.optString("sigAlgorithm", null);
        keyset.kemAlgorithm = json.optString("kemAlgorithm", null);
        keyset.publicSigKey = json.optString("publicSigKey", null);
        keyset.privateSigKey = json.optString("privateSigKey", null);
        keyset.publicKemKey = json.optString("publicKemKey", null);
        keyset.privateKemKey = json.optString("privateKemKey", null);

        keyStore.put(accountId, keyset);
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void saveRemotePublicKey(
        Context context,
        String emailAddress,
        String sigAlgorithm,
        String publicSigKey,
        String kemAlgorithm,
        String publicKemKey
    ) throws Exception {

        JSONObject json = new JSONObject();

        if (sigAlgorithm != null && publicSigKey != null) {
            if (!Sigs.is_sig_enabled(sigAlgorithm)) {
                throw new IllegalArgumentException("Signaturalgorithmus nicht unterstützt: " + sigAlgorithm);
            }

            json.put("sigAlgorithm", sigAlgorithm);
            json.put("publicSigKey", publicSigKey);
        }

        if (kemAlgorithm != null && publicKemKey != null) {
            if (!KEMs.is_KEM_enabled(kemAlgorithm)) {
                throw new IllegalArgumentException("KEM-Algorithmus nicht unterstützt: " + kemAlgorithm);
            }

            json.put("kemAlgorithm", kemAlgorithm);
            json.put("publicKemKey", publicKemKey);
        }

        if (json.length() == 0) {
            throw new IllegalArgumentException("Kein gültiger Schlüssel zum Speichern gefunden.");
        }

        SharedPreferences prefs = EncryptedSharedPreferences.create(
            "pqc_remote_pubkeys",
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        prefs.edit().putString(emailAddress.toLowerCase(), json.toString()).apply();
    }


    public static JSONObject loadRemotePublicKey(Context context, String emailAddress) throws Exception {
        SharedPreferences prefs = EncryptedSharedPreferences.create(
            "pqc_remote_pubkeys",
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        String json = prefs.getString(emailAddress.toLowerCase(), null);
        if (json == null) throw new Exception("Kein öffentlicher Schlüssel für: " + emailAddress);
        return new JSONObject(json);
    }
    public static void deleteKeyset(Context context, String accountId) throws Exception {
        // Entferne aus dem Cache (falls geladen)
        keyStore.remove(accountId);

        // Entferne aus EncryptedSharedPreferences
        SharedPreferences prefs = EncryptedSharedPreferences.create(
            "pqc_secure_keys",
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        prefs.edit().remove(accountId).apply();
    }

    public static Map<String, PqcKeyset> getKeyStore() {
        return keyStore;
    }
}
