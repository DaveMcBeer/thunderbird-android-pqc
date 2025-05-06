package com.fsck.k9.pqcExtension.helper.encryption;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.fsck.k9.mail.Part;
import com.fsck.k9.mail.internet.MimeBodyPart;
import com.fsck.k9.mailstore.BinaryMemoryBody;
import com.fsck.k9.mailstore.CryptoResultAnnotation;
import com.fsck.k9.mailstore.CryptoResultAnnotation.CryptoError;
import com.fsck.k9.pqcExtension.helper.PqcMessageHelper;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory;
import com.fsck.k9.pqcExtension.message.results.PqcDecryptionResult;
import org.apache.james.mime4j.util.MimeUtil;
import org.json.JSONObject;
import java.util.Base64;

public class PqcDecryptionHelper {

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

            byte[] plaintext = HybridEncryptionHelper.decryptHybridMessage(
                context,
                userId,
                encryptedPayload,
                rsaCiphertext,
                pqcCiphertext,
                pqcPrivateKey,
                pqcAlgorithm
            );

            // Erstelle den sichtbaren MIME-Part, der den verschlüsselten ersetzt
            MimeBodyPart replacementData = MimeBodyPart.create( new BinaryMemoryBody(plaintext, MimeUtil.ENC_BINARY),
                "application/octet-stream");

            // PQC-Entschlüsselungsergebnis (ohne SessionKeys)
            PqcDecryptionResult pqcResult = new PqcDecryptionResult(
                PqcDecryptionResult.RESULT_ENCRYPTED
            );

            // Korrekte Annotation mit replacementData als MIME-BodyPart
            return CryptoResultAnnotation.createPqcEncryptionSuccessAnnotation(
                pqcResult,
                replacementData
            );

        } catch (Exception e) {
            throw new RuntimeException("Fehler bei Hybrid-Entschlüsselung", e);
        }
    }

}
