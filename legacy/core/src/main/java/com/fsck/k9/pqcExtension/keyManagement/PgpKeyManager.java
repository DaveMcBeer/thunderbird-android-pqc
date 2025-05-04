package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build.VERSION_CODES;

import androidx.annotation.RequiresApi;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;

import com.fsck.k9.pqcExtension.keyManagement.PqcKeyManager.PqcKeyset;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class PgpKeyManager {
    private static final String PREF_NAME = "secure_pgp_keys";
    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 4096;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static final Map<String, KeyPair> keyStore = new HashMap<>();
    /**
     * Erzeugt ein neues Schlüsselpaar für den gegebenen Account und speichert es sicher.
     */
    @RequiresApi(api = VERSION_CODES.O)
    public static KeyPair generateAndStoreKeyPair(Context context, String accountId) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyGen.initialize(KEY_SIZE);
        KeyPair keyPair = keyGen.generateKeyPair();

        String publicKeyEncoded = Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKeyEncoded = Base64.getMimeEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        String pubKeyPref = accountId + "_pub";
        String privKeyPref = accountId + "_priv";

        EncryptedSharedPreferences.create(
                PREF_NAME,
                MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            ).edit()
            .putString(pubKeyPref, publicKeyEncoded)
            .putString(privKeyPref, privateKeyEncoded)
            .apply();

        return keyPair;
    }

    /**
     * Lädt das Schlüsselpaar für den gegebenen Account.
     * Gibt null zurück, wenn nichts gespeichert ist.
     */
    @RequiresApi(api = VERSION_CODES.O)
    public static KeyPair loadKeyPair(Context context, String accountId) throws Exception {
        String pubKeyPref = accountId + "_pub";
        String privKeyPref = accountId + "_priv";

        String publicKeyEncoded = EncryptedSharedPreferences.create(
            PREF_NAME,
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        ).getString(pubKeyPref, null);

        String privateKeyEncoded = EncryptedSharedPreferences.create(
            PREF_NAME,
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        ).getString(privKeyPref, null);

        if (publicKeyEncoded == null || privateKeyEncoded == null) {
            return null;
        }

        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getMimeDecoder().decode(publicKeyEncoded)));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(privateKeyEncoded)));

        return new KeyPair(publicKey, privateKey);
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    public static String exportPublicKeyArmored(PublicKey publicKey) throws Exception {
        PGPPublicKey pgpPublicKey = new JcaPGPKeyConverter()
            .getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey, new Date());

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(byteOut);

        pgpPublicKey.encode(armorOut);
        armorOut.close();

        return byteOut.toString(StandardCharsets.UTF_8.name());
    }

    @RequiresApi(api = VERSION_CODES.O)
    public static void saveRemotePublicKey(
        Context context,
        String emailAddress,
        String publicKeyArmored
    ) throws Exception {
        SharedPreferences prefs = EncryptedSharedPreferences.create(
            "pgp_remote_pubkeys",
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        prefs.edit().putString(emailAddress.toLowerCase(), publicKeyArmored).apply();
    }

    @RequiresApi(api = VERSION_CODES.O)
    public static String loadRemotePublicKey(Context context, String emailAddress) throws Exception {
        SharedPreferences prefs = EncryptedSharedPreferences.create(
            "pgp_remote_pubkeys",
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        String armoredKey = prefs.getString(emailAddress.toLowerCase(), null);
        if (armoredKey == null) throw new Exception("Kein öffentlicher PGP-Schlüssel gefunden für: " + emailAddress);
        return armoredKey;
    }

    @RequiresApi(api = VERSION_CODES.O)
    public static KeyPair loadKeyPairCached(Context context, String accountId) throws Exception {
        if (keyStore.containsKey(accountId)) {
            return keyStore.get(accountId);
        }

        KeyPair pair = loadKeyPair(context, accountId);
        if (pair != null) {
            keyStore.put(accountId, pair);
        }
        return pair;
    }
    @RequiresApi(api = VERSION_CODES.O)
    public static void deleteKeySet(Context context, String accountId) throws Exception {
        keyStore.remove(accountId);

        String pubKeyPref = accountId + "_pub";
        String privKeyPref = accountId + "_priv";

        SharedPreferences prefs = EncryptedSharedPreferences.create(
            PREF_NAME,
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );

        prefs.edit().remove(pubKeyPref).remove(privKeyPref).apply();
    }

    @RequiresApi(api = VERSION_CODES.O)
    public static void setKeyPair(Context context, String accountId, String publicKeyBase64, String privateKeyBase64) throws Exception {
        // 🔓 Decodiere Base64 Strings
        byte[] pubBytes = Base64.getDecoder().decode(publicKeyBase64);
        byte[] privBytes = Base64.getDecoder().decode(privateKeyBase64);

        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        // 🧠 Cache aktualisieren
        keyStore.put(accountId, keyPair);

        // 💾 Sicher speichern
        String pubKeyPref = accountId + "_pub";
        String privKeyPref = accountId + "_priv";

        EncryptedSharedPreferences.create(
                PREF_NAME,
                MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            ).edit()
            .putString(pubKeyPref, publicKeyBase64)
            .putString(privKeyPref, privateKeyBase64)
            .apply();
    }
    public static boolean hasKeyset(String accountId) {
        KeyPair keyPair = keyStore.get(accountId);
        return keyPair != null &&
            keyPair.getPublic() != null &&
            keyPair.getPrivate() != null;
    }
    public static Map<String, KeyPair> getKeyStore() {
        return keyStore;
    }
}
