package com.fsck.k9.pqcExtension.KeyDistribution;

import android.content.Context;
import android.util.Log;

import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.Message;
import com.fsck.k9.mail.Multipart;
import com.fsck.k9.mail.Part;
import com.fsck.k9.mail.internet.MimeUtility;
import com.fsck.k9.pqcExtension.helper.PqcMessageHelper;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStore;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory;
import com.fsck.k9.pqcExtension.keyManagement.SimpleKeyStoreFactory.KeyType;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

public class KeyReciever {

    private static final String TAG = "KeyReciever";

    /**
     * Scans a received message for public key attachments (PGP, PQC-KEM, PQC-SIG) and imports them
     * into the local key stores.
     */
    public static void importPublicKeysFromMessage(Context context, Message message, String accountId) {
        String senderEmail = message.getFrom()[0].getAddress();

        String pqcSigKey = null;
        String pqcKemKey = null;
        String pqcSigAlgorithm = null;
        String pqcKemAlgorithm = null;

        try {
            if (!(message.getBody() instanceof Multipart)) {
                Log.d(TAG, "Message body is not multipart");
                return;
            }

            Multipart multipart = (Multipart) message.getBody();

            // Iterate over each part to find public key attachments
            for (Part part : multipart.getBodyParts()) {
                if (!(part instanceof BodyPart)) continue;
                BodyPart bodyPart = (BodyPart) part;

                String disposition = bodyPart.getDisposition();
                if (disposition == null || !disposition.toLowerCase(Locale.US).startsWith("attachment")) {
                    continue;
                }

                String filename = MimeUtility.getHeaderParameter(disposition, "filename");
                if (filename == null) continue;

                String armoredText = extractAsciiContent(bodyPart);
                if (armoredText == null || !armoredText.contains("-----BEGIN")) continue;

                // Identify and store keys by filename
                if (filename.equalsIgnoreCase(KeyDistributor.KeyAttachment.PQC_SIG.filename)) {
                    pqcSigAlgorithm = PqcMessageHelper.extractAlgorithm(armoredText);
                    pqcSigKey = armoredText;

                } else if (filename.equalsIgnoreCase(KeyDistributor.KeyAttachment.PQC_KEM.filename)) {
                    pqcKemAlgorithm = PqcMessageHelper.extractAlgorithm(armoredText);
                    pqcKemKey = armoredText;

                } else if (filename.equalsIgnoreCase(KeyDistributor.KeyAttachment.PGP.filename)) {
                    // PGP is assumed to be fully armored already
                    SimpleKeyStore pgpStore = SimpleKeyStoreFactory.getKeyStore(KeyType.PGP);
                    pgpStore.importRemotePublicKey(context, accountId, senderEmail, "PGP", armoredText);
                    Log.i(TAG, "PGP-Key saved for: " + senderEmail);
                }
            }


            // Save PQC signature key if found
            if (pqcSigKey != null && pqcSigAlgorithm != null) {
                SimpleKeyStore sigStore = SimpleKeyStoreFactory.getKeyStore(KeyType.PQC_SIG);
                sigStore.importRemotePublicKey(context, accountId, senderEmail, pqcSigAlgorithm,
                    PqcMessageHelper.extractContent(pqcSigKey, "PQC SIGNATURE PUBLIC KEY"));
                Log.i(TAG, "PQC-SIG-Key saved for: " + senderEmail);
            }


            // Save PQC KEM key if found
            if (pqcKemKey != null && pqcKemAlgorithm != null) {
                SimpleKeyStore kemStore = SimpleKeyStoreFactory.getKeyStore(KeyType.PQC_KEM);
                kemStore.importRemotePublicKey(context, accountId, senderEmail, pqcKemAlgorithm,
                    PqcMessageHelper.extractContent(pqcKemKey, "PQC KEM PUBLIC KEY"));
                Log.i(TAG, "PQC-KEM-Key saved for: " + senderEmail);
            }

        } catch (Exception e) {
            Log.e(TAG, "Error while importing keys: ", e);
        }
    }


    /**
     * Extracts ASCII content from a body part. If content appears to be Base64-encoded,
     * decodes it first before interpreting it as ASCII-armored text.
     */
    private static String extractAsciiContent(BodyPart part) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            InputStream inputStream = part.getBody().getInputStream();
            byte[] buffer = new byte[4096];
            int n;
            while ((n = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, n);
            }

            String result = outputStream.toString(StandardCharsets.US_ASCII.name());

            // If no armor headers are detected, attempt to decode base64
            if (!result.contains("-----BEGIN")) {
                byte[] decoded = Base64.getMimeDecoder().decode(result.replaceAll("\\s+", ""));
                result = new String(decoded, StandardCharsets.US_ASCII);
            }

            return result;
        } catch (Exception e) {
            Log.e(TAG, "Error while reading attachment content", e);
            return null;
        }
    }
}
