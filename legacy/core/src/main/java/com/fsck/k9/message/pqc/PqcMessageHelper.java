package com.fsck.k9.message.pqc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.MessagingException;

public class PqcMessageHelper {

    /**
     * Canonicalize MIME content for PQC signature:
     * - normalize line endings to CRLF
     * - strip trailing whitespace
     */
    public static byte[] canonicalize(BodyPart part) throws IOException, MessagingException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        part.writeTo(outputStream);

        String canonicalized = outputStream.toString(StandardCharsets.UTF_8.name())
            .replaceAll("(?<!\r)\n", "\r\n")
            .replaceAll("[ \t]+\r\n", "\r\n");

        return canonicalized.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Encode raw bytes into ASCII-Armored Base64 format.
     * Example output:
     * -----BEGIN PQC SIGNATURE-----
     * base64 lines...
     * -----END PQC SIGNATURE-----
     */
    public static String toAsciiArmor(byte[] data, String label) {
        String base64 = Base64.getMimeEncoder().encodeToString(data);
        return String.format("-----BEGIN %s-----\r\n%s\r\n-----END %s-----", label, base64, label);
    }

    /**
     * Extract raw base64 content from an ASCII-armored block.
     */
    public static byte[] fromAsciiArmor(String armoredText, String label) throws IOException {
        String beginMarker = "-----BEGIN " + label + "-----";
        String endMarker = "-----END " + label + "-----";

        int beginIndex = armoredText.indexOf(beginMarker);
        int endIndex = armoredText.indexOf(endMarker);
        if (beginIndex == -1 || endIndex == -1 || endIndex <= beginIndex) {
            throw new IOException("Invalid ASCII armor format");
        }

        String contentBlock = armoredText.substring(beginIndex + beginMarker.length(), endIndex);
        String base64Data = contentBlock.replaceAll("\\s+", "");
        return Base64.getMimeDecoder().decode(base64Data);
    }

    /**
     * Decode MIME-safe Base64 (mit Umbrüchen erlaubt).
     */
    public static byte[] decodeBase64Mime(String base64) {
        return Base64.getMimeDecoder().decode(base64.replaceAll("\\s+", ""));
    }

    /**
     * MIME-safe Base64 Encoding (Zeilenumbrüche erlaubt, RFC 2045-konform).
     */
    public static String encodeBase64Mime(byte[] data) {
        return Base64.getMimeEncoder().encodeToString(data);
    }

    /**
     * Extrahiert MIME-Body als String, dekodiert base64 → rohe Bytes.
     */
    public static String extractAsciiContent(BodyPart part) throws IOException, MessagingException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        part.getBody().writeTo(outputStream);
        return outputStream.toString(StandardCharsets.US_ASCII.name());
    }
}
