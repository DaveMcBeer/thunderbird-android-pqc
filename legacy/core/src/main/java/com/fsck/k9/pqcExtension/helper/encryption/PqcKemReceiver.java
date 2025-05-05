package com.fsck.k9.pqcExtension.helper.encryption;


public class PqcKemReceiver {

    /**
     * Versucht, einen PQC KEM Part in einer empfangenen Nachricht zu finden und decapsuliert ihn.
     *
     * @param mimeMessage Die empfangene MIME-Nachricht
     * @param secretKey Das eigene PQC SecretKey (aus Account)
     * @param kemAlgorithm Der Name des verwendeten KEM Algorithmus (z.B. Kyber512)
     * @return Der abgeleitete Session-Key oder null, falls kein PQC Part vorhanden oder Fehler
     */
    /*public static byte[] tryExtractAndDecapsulatePqcKem(MimeMessage mimeMessage, byte[] secretKey, String kemAlgorithm) {
        try {
            if (!(mimeMessage.getBody() instanceof MimeMultipart)) {
                return null;
            }

            MimeMultipart multipart = (MimeMultipart) mimeMessage.getBody();

            for (int i = 0; i < multipart.getCount(); i++) {
                BodyPart part = multipart.getBodyPart(i);
                String contentType = part.getHeader(MimeHeader.HEADER_CONTENT_TYPE)[0];

                if (contentType != null && contentType.toLowerCase().startsWith("application/pqc-kem-encapsulation")) {
                    String base64Ciphertext =  PqcMessageHelper.extractAsciiContent(part);
                    byte[] ciphertext = PqcMessageHelper.decodeBase64Mime(base64Ciphertext);

                    try {
                        KeyEncapsulation kem = new KeyEncapsulation(kemAlgorithm, secretKey);
                        byte[] sharedSecret = kem.decap_secret(ciphertext);
                        kem.dispose_KEM();

                        // Erfolgreiche Decapsulation → HKDF ableiten und zurückgeben
                        return CryptoUtils.INSTANCE.hkdfSha256(sharedSecret, "PQC-KEM-OpenPGP", 32);
                    } catch (Exception e) {
                        // Decapsulation fehlgeschlagen, probiere nächstes Attachment
                        continue;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    private static String extractRecipientFromContentType(String contentType) {
        try {
            int startIndex = contentType.indexOf("recipient=");
            if (startIndex == -1) {
                return null;
            }
            startIndex += "recipient=".length();
            String recipient = contentType.substring(startIndex).trim();
            if (recipient.startsWith("\"")) {
                recipient = recipient.substring(1);
            }
            int endQuote = recipient.indexOf("\"");
            if (endQuote != -1) {
                recipient = recipient.substring(0, endQuote);
            }
            return recipient;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }*/

}
