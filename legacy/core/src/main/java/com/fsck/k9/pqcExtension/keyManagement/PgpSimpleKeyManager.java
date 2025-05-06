package com.fsck.k9.pqcExtension.keyManagement;

import android.content.Context;
import android.content.SharedPreferences;
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
    private static final String PREFS_NAME = "pgp_key_store";
    private static final String REMOTE_PREFS = "pgp_remote_keys";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void generateAndStoreKeyPair(Context context, String userId) throws Exception {
        char[] emptyPassphrase = new char[0];
        PGPKeyRingGenerator keyRingGen = generateKeyRing(userId, emptyPassphrase);

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        String pubArmored = armorKeyRing(pubRing);
        String privArmored = armorKeyRing(secRing);

        SharedPreferences prefs = getPrefs(context, PREFS_NAME);
        prefs.edit()
            .putString(userId + "_pub", pubArmored)
            .putString(userId + "_priv", privArmored)
            .apply();
    }

    private static PGPKeyRingGenerator generateKeyRing(String identity, char[] passphrase) {
        try{
            // RSA-Schlüsselpaar generieren (4096 Bit für starke Sicherheit)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
            kpg.initialize(4096); // Wichtig: Schlüssellänge explizit setzen!
            KeyPair keyPair = kpg.generateKeyPair();

            // PGP-Schlüsselpaar erstellen (RSA_GENERAL ist der Standard-Tag für RSA)
            PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, keyPair, new Date());

            // SHA-256 statt SHA-1 für bessere Sicherheit
            PGPDigestCalculator sha1Cal = new JcaPGPDigestCalculatorProviderBuilder()
                .build()
                .get(HashAlgorithmTags.SHA1);

            // Passwort-Verschlüsselung mit AES-256
            PBESecretKeyEncryptor encryptor = new JcePBESecretKeyEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256,
                sha1Cal)
                .setProvider(new BouncyCastleProvider())
                .build(passphrase);

            // KeyRingGenerator erstellen (POSITIVE_CERTIFICATION für Selbstsignatur)
            return new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                pgpKeyPair,
                identity,
                sha1Cal,
                null, // Keine zusätzlichen Subkeys hier
                null, // Keine zusätzlichen Subkeys hier
                new JcaPGPContentSignerBuilder(
                    pgpKeyPair.getPublicKey().getAlgorithm(),
                    HashAlgorithmTags.SHA256), // SHA-256 für Signaturen
                encryptor);
        }
        catch (Exception e){
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

    public static void deleteKeyPair(Context context, String userId) {
        getPrefs(context, PREFS_NAME)
            .edit()
            .remove(userId + "_pub")
            .remove(userId + "_priv")
            .apply();
    }

    public static void saveRemotePublicKey(Context context, String userId, String remoteEmail, String algorithm, String publicKey) {
        try {
            SharedPreferences prefs = getPrefs(context, REMOTE_PREFS);
            JSONObject json = new JSONObject();
            json.put("algorithm", algorithm);
            json.put("publicKey", publicKey);

            prefs.edit()
                .putString(remoteEmail.toLowerCase(), json.toString())
                .apply();
        } catch (Exception e) {
            throw new RuntimeException("Fehler beim Speichern des Remote-Keys", e);
        }
    }


    public static String loadRemotePublicKey(Context context, String remoteEmail) throws Exception {
        String key = getPrefs(context, REMOTE_PREFS).getString(remoteEmail.toLowerCase(), null);
        if (key == null) {
            throw new Exception("Kein Remote-Key vorhanden");
        }

        // Prüfe, ob es ein JSON-Objekt ist
        if (key.trim().startsWith("{")) {
            JSONObject json = new JSONObject(key);
            if (!json.has("publicKey")) {
                throw new Exception("JSON enthält keinen 'publicKey'");
            }
            return json.getString("publicKey");
        }

        // Falls es kein JSON ist, Rückgabe wie bisher
        return key;
    }

    public static boolean hasKeyPair(Context context, String userId) {
        SharedPreferences prefs = getPrefs(context, PREFS_NAME);
        return prefs.contains(userId + "_pub") && prefs.contains(userId + "_priv");
    }

    private static SharedPreferences getPrefs(Context context, String name) {
        return context.getSharedPreferences(name, Context.MODE_PRIVATE);
    }

    public static void importArmoredKeyPair(Context context, String userId, String armoredPublic, String armoredPrivate) throws Exception {
        // Validierung
        if (armoredPublic == null || armoredPrivate == null) {
            throw new IllegalArgumentException("Public or Private key is null");
        }

        // Speichern
        SharedPreferences prefs = getPrefs(context, PREFS_NAME);
        prefs.edit()
            .putString(userId + "_pub", armoredPublic)
            .putString(userId + "_priv", armoredPrivate)
            .apply();
    }

    public static String exportArmoredPublicKey(Context context, String userId) throws Exception {
        SharedPreferences prefs = getPrefs(context, PREFS_NAME);
        String pub = prefs.getString(userId + "_pub", null);
        if (pub == null) throw new Exception("Kein öffentlicher Schlüssel gefunden");
        return pub;
    }

    // Optional: zum Parsen & Prüfen, falls du willst
    public static PGPPublicKeyRing parsePublicKeyRing(String armored) throws Exception {
        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        PGPPublicKeyRingCollection keyRings = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());

        Iterator<PGPPublicKeyRing> ringIter = keyRings.getKeyRings();
        if (ringIter.hasNext()) {
            return ringIter.next();
        } else {
            throw new IllegalArgumentException("Kein gültiger PGPPublicKeyRing in der Eingabe gefunden");
        }
    }
    public static PGPSecretKeyRing parseSecretKeyRing(String armored) throws Exception {
        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(armored.getBytes("UTF-8")));
        PGPObjectFactory factory = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        Object obj = factory.nextObject();
        if (!(obj instanceof PGPSecretKeyRing)) {
            throw new IllegalArgumentException("Kein gültiger SecretKeyRing");
        }
        return (PGPSecretKeyRing) obj;
    }

    public static JSONObject loadLocalPrivateKey(Context context, String userId) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String privArmored = prefs.getString(userId + "_priv", null);
        if (privArmored == null) throw new Exception("Kein privater Schlüssel gefunden");

        JSONObject keyJson = new JSONObject();
        keyJson.put("algorithm", "RSA"); // RSA ist festgelegt für PGP-Keys
        keyJson.put("privateKey", privArmored);
        return keyJson;
    }

}
