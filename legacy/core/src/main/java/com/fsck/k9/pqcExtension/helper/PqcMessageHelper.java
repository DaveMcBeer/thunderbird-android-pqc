package com.fsck.k9.pqcExtension.helper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.os.Build.VERSION_CODES;

import androidx.annotation.RequiresApi;
import com.fsck.k9.mail.Body;
import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.Multipart;
import com.fsck.k9.mail.Part;
import com.fsck.k9.mailstore.BinaryMemoryBody;


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

    @RequiresApi(api = VERSION_CODES.TIRAMISU)
    public static byte[] extractEncryptedPayload(Part part) throws Exception {
        if (!(part.getBody() instanceof Multipart)) {
            throw new IllegalArgumentException("Expected Multipart body");
        }

        Multipart multipart = (Multipart) part.getBody();

        for (BodyPart bodyPart : multipart.getBodyParts()) {
            if (bodyPart.isMimeType("application/octet-stream")) {
                Body innerBody = bodyPart.getBody();

                if (!(innerBody instanceof BinaryMemoryBody)) {
                    throw new IllegalArgumentException("Unexpected body type: " + innerBody.getClass().getSimpleName());
                }

                BinaryMemoryBody binaryBody = (BinaryMemoryBody) innerBody;
                byte[] rawBytes = binaryBody.getInputStream().readAllBytes();

                // 1. Base64-Rohdaten (als Text)
                String rawText = new String(rawBytes, StandardCharsets.US_ASCII);
                System.out.println("📦 Base64-Rohtext (erste 100 Zeichen):");
                System.out.println(rawText.substring(0, Math.min(100, rawText.length())));

                // 2. Prüfung: Nur gültige Base64-Zeichen
                if (!rawText.matches("[A-Za-z0-9+/=\\r\\n]+")) {
                    throw new IllegalArgumentException("Ungültige Zeichen in Base64-Daten gefunden");
                }

                // 3. Dekodierung mit MIME-kompatiblem Decoder (erlaubt \r\n)
                byte[] decoded = Base64.getMimeDecoder().decode(rawText);

                System.out.println("✅ Dekodiert: Länge = " + decoded.length + " Bytes");
                return decoded;
            }
        }

        throw new Exception("⚠️ Kein verschlüsselter Payload-Part gefunden");
    }




}
