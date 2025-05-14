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

    /**
     * Creates an ASCII-armored string from content, with a header and algorithm info.
     * Format:
     * -----BEGIN [header]-----
     * Algorithm: [algorithm]
     * [content]
     * -----END [header]-----
     */
    public static String armor(String content, String header, String algorithm) {
        return "-----BEGIN " + header + "-----\n" +
            "Algorithm: " + algorithm + "\n\n" +
            content + "\n" +
            "-----END " + header + "-----";
    }

    /**
     * Extracts the content section from an armored message block.
     * It searches for the block matching the given header and parses the content within.
     *
     * @param armoredText  The full armored message
     * @param header       The type of header to match (e.g. "PQC SIGNATURE")
     * @return             The base64-encoded payload inside the armored block
     * @throws Exception   If the block or content could not be found
     */
    public static String extractContent(String armoredText, String header) throws Exception {
        String pattern = "-----BEGIN " + Pattern.quote(header) + "-----(.*?)-----END " + Pattern.quote(header) + "-----";
        Pattern r = Pattern.compile(pattern, Pattern.DOTALL);
        Matcher m = r.matcher(armoredText);
        if (!m.find()) {
            throw new Exception("Kein gültiger armierter Block gefunden");
        }

        String block = m.group(1).trim();

        // Try to split off headers from content using double line break
        String[] parts = block.split("\\n\\n", 2);
        if (parts.length == 2) {
            return parts[1].trim();
        }

        // Fallback: scan for lines that match Base64 only
        StringBuilder base64 = new StringBuilder();
        boolean base64Started = false;
        for (String line : block.split("\\r?\\n")) {
            if (line.matches("^[A-Za-z0-9+/=]+$")) {
                base64Started = true;
                base64.append(line).append("\n");
            } else if (base64Started) {
                break; // Stop at first non-Base64 line after block started
            }
        }

        if (base64.length() == 0) {
            throw new Exception("Fehlendes Content-Segment");
        }

        return base64.toString().trim();
    }

    /**
     * Cleans a Base64 string by removing whitespace and non-Base64 lines.
     * Ensures decoding compatibility even with wrapped text.
     */
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


    /**
     * Extracts the algorithm name from the header line of an armored message.
     * @throws Exception if no algorithm is found
     */
    public static String extractAlgorithm(String armoredText) throws Exception {
        Pattern pattern = Pattern.compile("Algorithm:\\s*(.+)");
        Matcher matcher = pattern.matcher(armoredText);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        throw new Exception("Algorithm not found");
    }

    /**
     * Canonicalizes a MIME part to a normalized byte representation with \r\n newlines.
     * This is necessary for correct signature verification.
     */
    public static byte[] canonicalize(Part part) throws Exception {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        part.writeTo(baos);
        return baos.toString(StandardCharsets.UTF_8.name())
            .replaceAll("(\r\n|\r|\n)", "\r\n")
            .getBytes(StandardCharsets.UTF_8);
    }


    /**
     * Extracts the encrypted payload (Base64 + Binary) from a multipart message.
     * Verifies content type and structure before decoding.
     */
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

                String rawText = new String(rawBytes, StandardCharsets.US_ASCII);

                // Validate Base64 characters
                if (!rawText.matches("[A-Za-z0-9+/=\\r\\n]+")) {
                    throw new IllegalArgumentException("Invalid characters found in Base64 data");
                }

                // Decode using MIME-compatible Base64 decoder
                return Base64.getMimeDecoder().decode(rawText);
            }
        }

        throw new Exception("No encrypted Payload-Part found");
    }
}
