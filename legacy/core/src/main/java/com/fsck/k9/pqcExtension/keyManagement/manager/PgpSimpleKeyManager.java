package com.fsck.k9.pqcExtension.keyManagement.manager;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Date;
import java.util.Iterator;

public class PgpSimpleKeyManager {
    private static final String PREFS_NAME = "pgp_key_store_secure";
    private static final String REMOTE_PREFS = "pgp_remote_keys";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static SharedPreferences getEncryptedPrefs(Context context, String name) throws Exception {
        MasterKey masterKey = new MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();

        return EncryptedSharedPreferences.create(
            context,
            name,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }

    public static void generateAndStoreKeyPair(Context context, String userId) throws Exception {
        char[] emptyPassphrase = new char[0];
        PGPKeyRingGenerator keyRingGen = generateKeyRing(userId, emptyPassphrase);

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        String pubArmored = armorKeyRing(pubRing);
        String privArmored = armorKeyRing(secRing);

        SharedPreferences prefs = getEncryptedPrefs(context, PREFS_NAME);
        prefs.edit()
            .putString(userId + "_pub", pubArmored)
            .putString(userId + "_priv", privArmored)
            .apply();
    }

    private static PGPKeyRingGenerator generateKeyRing(String identity, char[] passphrase) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
            kpg.initialize(4096);
            KeyPair keyPair = kpg.generateKeyPair();

            PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, keyPair, new Date());

            PGPDigestCalculator sha1Cal = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            PBESecretKeyEncryptor encryptor = new JcePBESecretKeyEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256, sha1Cal).setProvider(new BouncyCastleProvider()).build(passphrase);

            return new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                pgpKeyPair,
                identity,
                sha1Cal,
                null,
                null,
                new JcaPGPContentSignerBuilder(
                    pgpKeyPair.getPublicKey().getAlgorithm(),
                    HashAlgorithmTags.SHA256
                ),
                encryptor
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String armorKeyRing(PGPPublicKeyRing keyRing) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(out)) {
            keyRing.encode(armoredOut);
        }
        return out.toString("UTF-8");
    }

    private static String armorKeyRing(PGPSecretKeyRing keyRing) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ArmoredOutputStream armoredOut = new ArmoredOutputStream(out)) {
            keyRing.encode(armoredOut);
        }
        return out.toString("UTF-8");
    }

    public static void deleteKeyPair(Context context, String userId) throws Exception {
        getEncryptedPrefs(context, PREFS_NAME).edit()
            .remove(userId + "_pub")
            .remove(userId + "_priv")
            .apply();
    }

    public static void deleteAll(Context context) throws Exception {
        getEncryptedPrefs(context, PREFS_NAME).edit().clear().apply();
    }

    public static boolean hasKeyPair(Context context, String userId) throws Exception {
        SharedPreferences prefs = getEncryptedPrefs(context, PREFS_NAME);
        return prefs.contains(userId + "_pub") && prefs.contains(userId + "_priv");
    }

    public static void importArmoredKeyPair(Context context, String userId, String armoredPublic, String armoredPrivate) throws Exception {
        SharedPreferences prefs = getEncryptedPrefs(context, PREFS_NAME);
        prefs.edit()
            .putString(userId + "_pub", armoredPublic)
            .putString(userId + "_priv", armoredPrivate)
            .apply();
    }

    public static String exportArmoredPublicKey(Context context, String userId) throws Exception {
        SharedPreferences prefs = getEncryptedPrefs(context, PREFS_NAME);
        String pub = prefs.getString(userId + "_pub", null);
        if (pub == null) throw new Exception("Kein öffentlicher Schlüssel gefunden");
        return pub;
    }

    public static JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        SharedPreferences prefs = getEncryptedPrefs(context, PREFS_NAME);
        String privArmored = prefs.getString(userId + "_priv", null);
        if (privArmored == null) throw new Exception("Kein privater Schlüssel gefunden");

        JSONObject keyJson = new JSONObject();
        keyJson.put("algorithm", "RSA");
        keyJson.put("privateKey", privArmored);
        return keyJson;
    }

    public static PGPPublicKeyRing parsePublicKeyRing(String armored) throws Exception {
        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        PGPPublicKeyRingCollection keyRings = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> ringIter = keyRings.getKeyRings();
        if (ringIter.hasNext()) return ringIter.next();
        else throw new IllegalArgumentException("Kein gültiger PGPPublicKeyRing");
    }

    public static PGPSecretKeyRing parseSecretKeyRing(String armored) throws Exception {
        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(armored.getBytes("UTF-8")));
        PGPObjectFactory factory = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        Object obj = factory.nextObject();
        if (!(obj instanceof PGPSecretKeyRing)) throw new IllegalArgumentException("Kein gültiger SecretKeyRing");
        return (PGPSecretKeyRing) obj;
    }

    public static void saveRemotePublicKey(Context context, String userId, String remoteEmail, String algorithm, String publicKey) {
        try {
            SharedPreferences prefs = context.getSharedPreferences(REMOTE_PREFS, Context.MODE_PRIVATE);
            JSONObject json = new JSONObject();
            json.put("algorithm", algorithm);
            json.put("publicKey", publicKey);
            prefs.edit().putString(remoteEmail.toLowerCase(), json.toString()).apply();
        } catch (Exception e) {
            throw new RuntimeException("Fehler beim Speichern des Remote-Keys", e);
        }
    }

    public static String loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        String key = context.getSharedPreferences(REMOTE_PREFS, Context.MODE_PRIVATE)
            .getString(remoteEmail.toLowerCase(), null);
        if (key == null) throw new Exception("Kein Remote-Key vorhanden");

        if (key.trim().startsWith("{")) {
            JSONObject json = new JSONObject(key);
            if (!json.has("publicKey")) throw new Exception("JSON enthält keinen 'publicKey'");
            return json.getString("publicKey");
        }

        return key;
    }
}
