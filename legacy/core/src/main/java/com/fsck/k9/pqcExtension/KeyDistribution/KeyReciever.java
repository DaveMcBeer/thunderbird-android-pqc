package com.fsck.k9.pqcExtension.KeyDistribution;

import android.content.Context;
import android.util.Log;

import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.Message;
import com.fsck.k9.mail.Multipart;
import com.fsck.k9.mail.Part;
import com.fsck.k9.mail.internet.MimeUtility;
import com.fsck.k9.pqcExtension.keyManagement.IKeyRegistry;
import com.fsck.k9.pqcExtension.keyManagement.KeyRegistryFactory;
import com.fsck.k9.pqcExtension.keyManagement.KeyRegistryFactory.KeyType;


import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

public class KeyReciever {

    private static final String TAG = "KeyReciever";

    public static void importPublicKeysFromMessage(Context context, Message message) {
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

                if (filename.equalsIgnoreCase(KeyDistributor.KeyAttachment.PQC_SIG.filename)) {
                    pqcSigAlgorithm = extractAlgorithmFromArmored(armoredText);
                    if (pqcSigAlgorithm == null) {
                        Log.w(TAG, "Signaturalgorithmus fehlt im Header");
                        continue;
                    }
                    pqcSigKey = decodeBase64FromArmored(armoredText);

                } else if (filename.equalsIgnoreCase(KeyDistributor.KeyAttachment.PQC_KEM.filename)) {
                    pqcKemAlgorithm = extractAlgorithmFromArmored(armoredText);
                    if (pqcKemAlgorithm == null) {
                        Log.w(TAG, "KEM Algorithmus fehlt im Header");
                        continue;
                    }
                    pqcKemKey = decodeBase64FromArmored(armoredText);
                } else if (filename.equalsIgnoreCase(KeyDistributor.KeyAttachment.PGP.filename)) {
                    IKeyRegistry pgpRegistry = KeyRegistryFactory.getRegistry(KeyType.PGP);
                    pgpRegistry.saveRemotePublicKey(context, senderEmail, armoredText);
                    Log.i(TAG, "PGP-Key gespeichert für: " + senderEmail);
                }
            }

            if ((pqcKemKey != null && pqcKemAlgorithm != null) || (pqcSigKey != null && pqcSigAlgorithm != null)) {
                IKeyRegistry pqcRegistry = KeyRegistryFactory.getRegistry(KeyType.PQC);
                pqcRegistry.saveRemotePublicKey(
                    context,
                    senderEmail,
                    pqcSigAlgorithm,
                    pqcSigKey,
                    pqcKemAlgorithm,
                    pqcKemKey
                );
                Log.i(TAG, "PQC-Key gespeichert für: " + senderEmail);
            }


        } catch (Exception e) {
            Log.e(TAG, "Fehler beim Importieren der Schlüssel: ", e);
        }
    }

    private static String getHeaderOrNull(BodyPart part, String name) {
        String[] values = part.getHeader(name);
        return (values != null && values.length > 0) ? values[0] : null;
    }

    private static String extractAsciiContent(BodyPart part) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            InputStream inputStream = part.getBody().getInputStream();
            byte[] buffer = new byte[4096];
            int n;
            while ((n = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, n);
            }

            // Versuche zuerst, den Inhalt als ASCII zu interpretieren
            String result = outputStream.toString(StandardCharsets.US_ASCII.name());

            // Falls kein BEGIN-Block sichtbar ist, versuche zu dekodieren
            if (!result.contains("-----BEGIN")) {
                byte[] decoded = Base64.getDecoder().decode(result.replaceAll("\\s+", ""));
                result = new String(decoded, StandardCharsets.US_ASCII);
            }

            return result;
        } catch (Exception e) {
            Log.e(TAG, "Fehler beim Lesen des Attachment-Inhalts", e);
            return null;
        }
    }

    private static String decodeBase64FromArmored(String armoredText) {
        try {
            String[] lines = armoredText.split("\r?\n");
            StringBuilder base64Builder = new StringBuilder();
            for (String line : lines) {
                if (line.startsWith("-----") || line.startsWith("Algorithm:") || line.trim().isEmpty()) {
                    continue;
                }
                base64Builder.append(line.trim());
            }
            return base64Builder.toString();
        } catch (Exception e) {
            Log.e(TAG, "Fehler beim Extrahieren aus ASCII-Armoring", e);
            return null;
        }
    }
    private static String extractAlgorithmFromArmored(String armoredText) {
        for (String line : armoredText.split("\r?\n")) {
            if (line.startsWith("Algorithm:")) {
                return line.substring("Algorithm:".length()).trim();
            }
        }
        return null;
    }

}
