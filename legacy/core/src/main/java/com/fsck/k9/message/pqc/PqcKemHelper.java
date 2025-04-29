package com.fsck.k9.message.pqc;

import java.nio.charset.StandardCharsets;

import com.fsck.k9.logging.Timber;
import com.fsck.k9.mail.BodyPart;
import com.fsck.k9.mail.Message;
import com.fsck.k9.mail.internet.MimeHeader;
import com.fsck.k9.mail.internet.MimeMultipart;
import org.apache.commons.io.IOUtils;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;


public class PqcKemHelper {

    public static class EncapsulationResult {
        private final byte[] ciphertext;
        private final byte[] sharedSecret;

        public EncapsulationResult(byte[] ciphertext, byte[] sharedSecret) {
            this.ciphertext = ciphertext;
            this.sharedSecret = sharedSecret;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public byte[] getSharedSecret() {
            return sharedSecret;
        }
    }

    public static EncapsulationResult encapsulate(byte[] recipientPublicKey, String kemAlgorithm) throws Exception {
        KeyEncapsulation kem = null;
        try {
            kem = new KeyEncapsulation(kemAlgorithm);

            Pair<byte[], byte[]> encapsulated = kem.encap_secret(recipientPublicKey);

            byte[] ciphertext = encapsulated.getLeft();
            byte[] sharedSecret = encapsulated.getRight();

            return new EncapsulationResult(ciphertext, sharedSecret);

        } catch (Exception e) {
            throw new Exception("Error during PQC-KEM encapsulation", e);
        } finally {
            if (kem != null) {
                kem.dispose_KEM();
            }
        }
    }

    public static void importPqcPublicKeyIfAvailable(Message message) {
        try {
            if (!(message.getBody() instanceof MimeMultipart)) {
                return;
            }

            MimeMultipart multipart = (MimeMultipart) message.getBody();
            for (int i = 0; i < multipart.getCount(); i++) {
                BodyPart part = multipart.getBodyPart(i);

                String[] contentType = part.getHeader(MimeHeader.HEADER_CONTENT_TYPE);
                if (contentType == null || contentType.length == 0) {
                    continue;
                }

                if (contentType[0].toLowerCase().startsWith("application/pqc-kem-public-key")) {
                    String publicKeyArmored = IOUtils.toString(part.getBody().getInputStream(), StandardCharsets.US_ASCII);

                    // Entarme den Key
                    byte[] publicKey = PqcMessageHelper.fromAsciiArmor(publicKeyArmored, "PQC KEM PUBLIC KEY");

                    // Hole die Absenderadresse
                    String fromAddress = message.getFrom()[0].getAddress();

                    String[] kemAlgorithmHeader = part.getHeader("X-PQC-KEM-Algorithm");
                    String kemAlgorithm = kemAlgorithmHeader != null && kemAlgorithmHeader.length > 0
                        ? kemAlgorithmHeader[0]
                        : "None"; // fallback falls header fehlt

                    // In den ContactStore speichern
                    PqcContactStore.INSTANCE.saveContact(fromAddress, kemAlgorithm, publicKey);

                    Timber.d("PQC Public Key erfolgreich von %s importiert!", fromAddress);
                    return;
                }
            }
        } catch (Exception e) {
            Timber.e(e, "Fehler beim Importieren des PQC Public Key");
        }
    }
}
