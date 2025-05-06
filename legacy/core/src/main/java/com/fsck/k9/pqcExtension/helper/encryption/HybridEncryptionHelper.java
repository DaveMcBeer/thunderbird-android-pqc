package com.fsck.k9.pqcExtension.helper.encryption;

import android.content.Context;

import com.fsck.k9.pqcExtension.keyManagement.PgpSimpleKeyManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;


public class HybridEncryptionHelper {

    public static class HybridKEMResult {
        public final byte[] rsaCiphertext;
        public final byte[] pqcCiphertext;
        public final byte[] sessionKey;

        public HybridKEMResult(byte[] rsaCt, byte[] pqcCt, byte[] sessionKey) {
            this.rsaCiphertext = rsaCt;
            this.pqcCiphertext = pqcCt;
            this.sessionKey = sessionKey;
        }
    }

    // === Hybrid-KEM: RSA + PQC ===
    public static HybridKEMResult encapsulateBoth(PGPPublicKey rsaPubKey, byte[] pqcPublicKey, String pqcAlgorithm) throws Exception {
       try{
           // Schritt 1: Zufälliges Shared Secret erzeugen (klassisch)
           byte[] rsaSharedSecret = new byte[32];
           new SecureRandom().nextBytes(rsaSharedSecret);

           // Schritt 2: RSA-KEM – Verschlüsselung des Shared Secret
           Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", new BouncyCastleProvider());
           PublicKey jceRsaPublic = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider()).getPublicKey(rsaPubKey);
           rsaCipher.init(Cipher.ENCRYPT_MODE, jceRsaPublic);
           byte[] rsaCiphertext = rsaCipher.doFinal(rsaSharedSecret);

           // Schritt 3: PQC-KEM durchführen
           KeyEncapsulation kem = new KeyEncapsulation(pqcAlgorithm);
           Pair<byte[], byte[]> pqcPair = kem.encap_secret(pqcPublicKey);
           kem.dispose_KEM();

           byte[] pqcCiphertext = pqcPair.getLeft();
           byte[] pqcSharedSecret = pqcPair.getRight();

           // Schritt 4: Ableiten des Session Keys
           byte[] sessionKey = deriveSessionKey(rsaSharedSecret, pqcSharedSecret);

           return new HybridKEMResult(rsaCiphertext, pqcCiphertext, sessionKey);
       }
       catch (Exception e){
           throw new RuntimeException(e);
       }

    }

    public static byte[] deriveRsaSharedSecretFromPrivateKey(Context context, String userId, byte[] encryptedSessionKey) throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        String armoredPriv = context.getSharedPreferences("pgp_key_store", Context.MODE_PRIVATE)
            .getString(userId + "_priv", null);

        PGPSecretKeyRing secretKeyRing = PgpSimpleKeyManager.parseSecretKeyRing(armoredPriv);
        PGPSecretKey decryptKey = null;

        for (PGPSecretKey key : secretKeyRing) {
            if (key.getPublicKey().isEncryptionKey()) {
                decryptKey = key;
                break;
            }
        }
        if (decryptKey == null) throw new Exception("No encryption key found");

        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider()).build(new char[0]);
        PGPPrivateKey privateKey = decryptKey.extractPrivateKey(decryptor);

        PrivateKey jcePrivateKey = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider()).getPrivateKey(privateKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, jcePrivateKey);
        return cipher.doFinal(encryptedSessionKey);
    }

    public static byte[] derivePqcSharedSecret(byte[] pqcCiphertext, byte[] pqcPrivateKey, String pqcAlgorithm) {
        KeyEncapsulation kem = new KeyEncapsulation(pqcAlgorithm, pqcPrivateKey);
        byte[] pqcSharedSecret = kem.decap_secret(pqcCiphertext);
        kem.dispose_KEM();
        return pqcSharedSecret;
    }

    public static byte[] deriveSessionKey(byte[] s1, byte[] s2) throws Exception {
        byte[] input = ByteBuffer.allocate(s1.length + s2.length).put(s1).put(s2).array();
        SecretKeySpec keySpec = new SecretKeySpec("hybrid-key-ctx".getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(input);
    }

    public static byte[] encryptWithAes(byte[] plaintext, byte[] sessionKey) throws Exception {
       try{
           byte[] iv = new byte[12];
           new SecureRandom().nextBytes(iv);

           Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
           SecretKey key = new SecretKeySpec(sessionKey, 0, 32, "AES");
           GCMParameterSpec spec = new GCMParameterSpec(128, iv);
           cipher.init(Cipher.ENCRYPT_MODE, key, spec);

           byte[] ciphertext = cipher.doFinal(plaintext);

           ByteBuffer buffer = ByteBuffer.allocate(4 + iv.length + ciphertext.length);
           buffer.putInt(iv.length);
           buffer.put(iv);
           buffer.put(ciphertext);
           return buffer.array();
       }
       catch (Exception e){
           throw new RuntimeException(e);
       }
    }

    public static byte[] decryptWithAes(byte[] encrypted, byte[] sessionKey) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(encrypted);
        int ivLength = buffer.getInt();
        byte[] iv = new byte[ivLength];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey key = new SecretKeySpec(sessionKey, 0, 32, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(ciphertext);
    }

    public static byte[] decryptHybridMessage(Context context, String userId, byte[] encryptedAesData, byte[] rsaKemCiphertext, byte[] pqcKemCiphertext, byte[] pqcPrivateKey, String pqcAlgorithm) throws Exception {
        byte[] rsaSharedSecret = deriveRsaSharedSecretFromPrivateKey(context, userId, rsaKemCiphertext);
        byte[] pqcSharedSecret = derivePqcSharedSecret(pqcKemCiphertext, pqcPrivateKey, pqcAlgorithm);
        byte[] sessionKey = deriveSessionKey(rsaSharedSecret, pqcSharedSecret);
        return decryptWithAes(encryptedAesData, sessionKey);
    }

    public static byte[] encryptHybridMessage(PGPPublicKey rsaPubKey, byte[] pqcPublicKey, String pqcAlgorithm, byte[] plaintext) throws Exception {
        HybridKEMResult kemResult = encapsulateBoth(rsaPubKey, pqcPublicKey, pqcAlgorithm);
        return encryptWithAes(plaintext, kemResult.sessionKey);
    }

    public static String foldHeaderValue(String value) {
        StringBuilder folded = new StringBuilder();
        int maxLineLength = 76; // konservativer Bruch
        for (int i = 0; i < value.length(); i += maxLineLength) {
            int end = Math.min(i + maxLineLength, value.length());
            folded.append(value, i, end);
            if (end < value.length()) {
                folded.append("\r\n "); // MIME-Continuation
            }
        }
        return folded.toString();
    }


}
