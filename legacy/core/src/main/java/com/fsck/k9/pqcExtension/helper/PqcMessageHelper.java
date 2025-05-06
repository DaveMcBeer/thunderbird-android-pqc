package com.fsck.k9.pqcExtension.helper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fsck.k9.mail.Part;


public class PqcMessageHelper {

    public static String armor(String content, String header, String algorithm) {
        return "-----BEGIN " + header + "-----\n" +
            "Algorithm: " + algorithm + "\n\n" +
            content + "\n" +
            "-----END " + header + "-----";
    }

    public static String extractContent(String armoredText, String header) throws Exception {
        String pattern = "-----BEGIN " + Pattern.quote(header) + "-----(.*?)-----END " + Pattern.quote(header) + "-----";
        Pattern r = Pattern.compile(pattern, Pattern.DOTALL);
        Matcher m = r.matcher(armoredText);
        if (!m.find()) {
            throw new Exception("Kein gültiger armierter Block gefunden");
        }

        String block = m.group(1).trim();

        // Versuche, mit oder ohne Doppel-Umbruch den Content zu finden
        String[] parts = block.split("\\n\\n", 2);
        if (parts.length == 2) {
            return parts[1].trim();
        }

        // Fallback: Suche erste Zeile mit Base64-Daten (ignoriert mögliche Header-Zeilen wie Algorithm: ...)
        StringBuilder base64 = new StringBuilder();
        boolean base64Started = false;
        for (String line : block.split("\\r?\\n")) {
            if (line.matches("^[A-Za-z0-9+/=]+$")) {
                base64Started = true;
                base64.append(line).append("\n");
            } else if (base64Started) {
                break; // Wenn Base64 beendet ist, hör auf
            }
        }

        if (base64.length() == 0) {
            throw new Exception("Fehlendes Content-Segment");
        }

        return base64.toString().trim();
    }
    public static byte[] decodeCleanBase64(String input) {
        StringBuilder clean = new StringBuilder();
        for (String line : input.split("\\r?\\n")) {
            line = line.trim();
            if (!line.isEmpty() && line.matches("^[A-Za-z0-9+/=]+$")) {
                clean.append(line);
            }
        }
        return Base64.getDecoder().decode(clean.toString());
    }

    public static String extractAlgorithm(String armoredText) throws Exception {
        Pattern pattern = Pattern.compile("Algorithm:\\s*(.+)");
        Matcher matcher = pattern.matcher(armoredText);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        throw new Exception("Algorithmus nicht gefunden");
    }


    public static byte[] canonicalize(Part part) throws Exception {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        part.writeTo(baos);
        return baos.toString(StandardCharsets.UTF_8.name())
            .replaceAll("(\r\n|\r|\n)", "\r\n")
            .getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] extractEncryptedPayload(Part part) throws Exception {
        String armoredText = new String(canonicalize(part), StandardCharsets.UTF_8);
        String payloadBase64 = extractContent(armoredText, "ENCRYPTED MESSAGE");
        return decodeCleanBase64(payloadBase64);
    }

}
