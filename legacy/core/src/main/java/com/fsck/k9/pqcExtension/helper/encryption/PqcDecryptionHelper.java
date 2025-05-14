package com.fsck.k9.pqcExtension.helper.encryption;

import android.content.Context;
import android.os.Build.VERSION_CODES;

import androidx.annotation.RequiresApi;

import com.fsck.k9.crypto.MessageCryptoStructureDetector;
import com.fsck.k9.mail.Part;
import com.fsck.k9.mail.internet.MimeBodyPart;
import com.fsck.k9.mail.internet.MimeMessage;
import com.fsck.k9.mailstore.CryptoResultAnnotation;
import com.fsck.k9.mailstore.MimePartStreamParser;
import com.fsck.k9.mailstore.util.FileFactory;
import com.fsck.k9.pqcExtension.helper.PqcMessageHelper;
import com.fsck.k9.pqcExtension.helper.signature.PqcSignatureVerifierHelper;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory;
import com.fsck.k9.pqcExtension.keyManagement.manager.PgpSimpleKeyManager;
import com.fsck.k9.pqcExtension.message.results.PqcDecryptionResult;

import com.fsck.k9.provider.DecryptedFileProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.json.JSONObject;
import org.openquantumsafe.KeyEncapsulation;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;

public class PqcDecryptionHelper {


    @RequiresApi(api = VERSION_CODES.TIRAMISU)
    public static CryptoResultAnnotation decrypt(Context context, Part part, String senderEmail, String userId) throws Exception {
        try {
            String rsaCiphertextBase64 = part.getHeader("X-Hybrid-RSA")[0];
            String pqcCiphertextBase64 = part.getHeader("X-Hybrid-PQC")[0];

            byte[] rsaCiphertext = Base64.getDecoder().decode(rsaCiphertextBase64.replaceAll("\\s", ""));
            byte[] pqcCiphertext = Base64.getDecoder().decode(pqcCiphertextBase64.replaceAll("\\s", ""));

            JSONObject keyData = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PQC_KEM)
                .loadLocalPrivateKey(context, userId);

            String pqcAlgorithm = keyData.getString("algorithm");
            byte[] pqcPrivateKey = Base64.getDecoder().decode(keyData.getString("privateKey"));

            byte[] encryptedPayload = PqcMessageHelper.extractEncryptedPayload(part);
            byte[] plaintext = decryptHybridMessage(
                context, userId,
                encryptedPayload, rsaCiphertext, pqcCiphertext,
                pqcPrivateKey, pqcAlgorithm
            );

            // ➕ Parsen der entschlüsselten Nachricht
            InputStream plaintextStream = new ByteArrayInputStream(plaintext);
            FileFactory fileFactory = DecryptedFileProvider.getFileFactory(context);
            MimeBodyPart replacementData = MimePartStreamParser.parse(fileFactory, plaintextStream);

            // 🔁 Falls keine Signatur vorhanden
            PqcDecryptionResult pqcResult = new PqcDecryptionResult(PqcDecryptionResult.RESULT_ENCRYPTED);

            // 🔍 Prüfen auf Signaturstruktur
            if (MessageCryptoStructureDetector.isMultipartSignedWithMultipleSignatures(replacementData)) {
                return PqcSignatureVerifierHelper.verifyAll(context, replacementData, senderEmail, userId,pqcResult);
            }


            return CryptoResultAnnotation.createPqcEncryptionSuccessAnnotation(pqcResult, replacementData);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static byte[] decryptWithAes(byte[] encrypted, byte[] sessionKey) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(encrypted);
        if (buffer.remaining() < 4) {
            throw new IllegalArgumentException("Encrypted data too short to contain IV length");
        }

        int ivLength = buffer.getInt();

        if (ivLength <= 0 || ivLength > 32 || buffer.remaining() < ivLength) {
            throw new IllegalArgumentException("Invalid IV length: " + ivLength);
        }

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

    public static byte[] deriveSessionKey(byte[] s1, byte[] s2) throws Exception {
        byte[] input = ByteBuffer.allocate(s1.length + s2.length).put(s1).put(s2).array();
        SecretKeySpec keySpec = new SecretKeySpec("hybrid-key-ctx".getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(input);
    }

    public static byte[] deriveRsaSharedSecretFromPrivateKey(Context context, String userId, byte[] encryptedSessionKey) throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        JSONObject json = SimpleKeyStoreFactory.getKeyStore(SimpleKeyStoreFactory.KeyType.PGP)
            .loadLocalPrivateKey(context, userId);

        String armoredPriv = json.getString("privateKey");

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

    public static byte[] decryptHybridMessage(Context context, String userId, byte[] encryptedAesData, byte[] rsaKemCiphertext, byte[] pqcKemCiphertext, byte[] pqcPrivateKey, String pqcAlgorithm) throws Exception {
        byte[] rsaSharedSecret = deriveRsaSharedSecretFromPrivateKey(context, userId, rsaKemCiphertext);
        byte[] pqcSharedSecret = derivePqcSharedSecret(pqcKemCiphertext, pqcPrivateKey, pqcAlgorithm);
        byte[] sessionKey = deriveSessionKey(rsaSharedSecret, pqcSharedSecret);
        return decryptWithAes(encryptedAesData, sessionKey);
    }

    public static byte[] derivePqcSharedSecret(byte[] pqcCiphertext, byte[] pqcPrivateKey, String pqcAlgorithm) {
        KeyEncapsulation kem = new KeyEncapsulation(pqcAlgorithm, pqcPrivateKey);
        byte[] pqcSharedSecret = kem.decap_secret(pqcCiphertext);
        kem.dispose_KEM();
        return pqcSharedSecret;
    }

}
