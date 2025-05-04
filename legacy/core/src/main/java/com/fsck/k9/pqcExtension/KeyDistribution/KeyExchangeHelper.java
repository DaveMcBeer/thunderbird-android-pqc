package com.fsck.k9.pqcExtension.KeyDistribution;

import android.util.Log;

import com.fsck.k9.mail.Body;
import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.Message;
import com.fsck.k9.mail.Multipart;
import com.fsck.k9.mail.Part;
import com.fsck.k9.mail.internet.MimeHeader;
import com.fsck.k9.pqcExtension.keyManagement.IKeyRegistry;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public class KeyExchangeHelper {

    private static final String TAG = "KeyExchangeHelper";

    public static void importPqcKeysFromMessage(Message message, IKeyRegistry pqcRegistry) {
        try {
            String senderEmail = message.getFrom()[0].getAddress();

            Body body = message.getBody();
            if (!(body instanceof Multipart)) return;

            Multipart multipart = (Multipart) body;
            for (Part part : multipart.getBodyParts()) {
                String disposition = part.getHeader(MimeHeader.HEADER_CONTENT_DISPOSITION)[0];
                if (disposition != null && disposition.contains("attachment")) {
                    String filename = extractFilename(disposition);
                    if (filename == null || !filename.endsWith(".asc")) continue;

                    String kemAlg = getHeader(part, "X-KEM-Algorithm");
                    String sigAlg = getHeader(part, "X-SIG-Algorithm");

                    String armoredKey = extractAsciiContent((BodyPart) part);

                    String json = "{\n" +
                        "  \"accountId\": \"" + senderEmail + "\",\n" +
                        "  \"sigAlgorithm\": \"" + sigAlg + "\",\n" +
                        "  \"kemAlgorithm\": \"" + kemAlg + "\",\n" +
                        (filename.contains("SIG") ? "  \"publicSigKey\"" : "  \"publicKemKey\"") +
                        ": \"" + armoredKey.replace("\n", "\\r\\n") + "\"\n}";

                    pqcRegistry.saveRemotePublicKey(null, senderEmail, json);
                    Log.i(TAG, "PQC-Key gespeichert für: " + senderEmail);
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Fehler beim Importieren des PQC-Keys", e);
        }
    }

    private static String extractFilename(String disposition) {
        int start = disposition.indexOf("filename=\"");
        if (start == -1) return null;
        int end = disposition.indexOf("\"", start + 10);
        return disposition.substring(start + 10, end);
    }

    private static String getHeader(Part part, String headerName) {
        String[] values = part.getHeader(headerName);
        return (values != null && values.length > 0) ? values[0] : "";
    }

    private static String extractAsciiContent(BodyPart part) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        part.getBody().writeTo(outputStream);
        return outputStream.toString(StandardCharsets.US_ASCII.name());
    }

    private String extractKey(String json, String keyName) {
        int i = json.indexOf("\"" + keyName + "\":\"");
        if (i == -1) throw new IllegalArgumentException("Key not found: " + keyName);
        int start = i + keyName.length() + 4;
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }
}
