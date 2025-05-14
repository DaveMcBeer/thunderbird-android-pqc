package com.fsck.k9.pqcExtension.helper.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;

public class PqcEncryptionHelper {

    /**
     * Container class holding the result of hybrid key encapsulation:
     * - RSA ciphertext
     * - PQC ciphertext
     * - Derived session key
     */
    public static class HybridKEMResult {
        public final byte[] rsaCiphertext;
        public final byte[] pqcCiphertext;
        public final byte[] sessionKey;

        public HybridKEMResult(byte[] rsaCt, byte[] pqcCt, byte[] sessionKey) {
            this.rsaCiphertext = rsaCt;
            this.pqcCiphertext = pqcCt;
            this.sessionKey = sessionKey;
        }
    }

    /**
     * Performs a hybrid key encapsulation using both classical RSA and post-quantum KEM.
     *
     * @param rsaPubKey      The classical RSA public key (OpenPGP format)
     * @param pqcPublicKey   The public key for the PQC KEM algorithm
     * @param pqcAlgorithm   The name of the PQC algorithm (e.g., "Kyber1024")
     * @return               A result object containing the encrypted secrets and session key
     * @throws Exception     If encryption fails at any stage
     */
    public static HybridKEMResult encapsulateBoth(PGPPublicKey rsaPubKey, byte[] pqcPublicKey, String pqcAlgorithm) throws Exception {
        try {
            // Step 1: Generate a 256-bit random shared secret for RSA
            byte[] rsaSharedSecret = new byte[32];
            new SecureRandom().nextBytes(rsaSharedSecret);

            // Step 2: Encrypt the RSA shared secret using RSA-OAEP
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", new BouncyCastleProvider());
            PublicKey jceRsaPublic = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider()).getPublicKey(rsaPubKey);
            rsaCipher.init(Cipher.ENCRYPT_MODE, jceRsaPublic);
            byte[] rsaCiphertext = rsaCipher.doFinal(rsaSharedSecret);

            // Step 3: Perform PQC KEM encapsulation
            KeyEncapsulation kem = new KeyEncapsulation(pqcAlgorithm);
            Pair<byte[], byte[]> pqcPair = kem.encap_secret(pqcPublicKey);
            kem.dispose_KEM();

            byte[] pqcCiphertext = pqcPair.getLeft();
            byte[] pqcSharedSecret = pqcPair.getRight();

            // Step 4: Derive the symmetric session key from both secrets
            byte[] sessionKey = PqcDecryptionHelper.deriveSessionKey(rsaSharedSecret, pqcSharedSecret);

            return new HybridKEMResult(rsaCiphertext, pqcCiphertext, sessionKey);
        } catch (Exception e) {
            throw new RuntimeException("Hybrid-KEM decryption failed", e);
        }
    }

    /**
     * Encrypts the given plaintext using AES-GCM with the derived session key.
     *
     * @param plaintext     The plaintext to encrypt
     * @param sessionKey    The 256-bit AES key used for encryption
     * @return              The IV and ciphertext packed together in a single byte array
     * @throws Exception    If AES encryption fails
     */
    public static byte[] encryptWithAes(byte[] plaintext, byte[] sessionKey) throws Exception {
        try {
            // Generate a random 96-bit IV for GCM
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);

            // Set up AES/GCM cipher instance
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey key = new SecretKeySpec(sessionKey, 0, 32, "AES");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            // Encrypt the plaintext
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Combine IV length, IV, and ciphertext into a single array
            ByteBuffer buffer = ByteBuffer.allocate(4 + iv.length + ciphertext.length);
            buffer.putInt(iv.length);
            buffer.put(iv);
            buffer.put(ciphertext);
            return buffer.array();
        } catch (Exception e) {
            throw new RuntimeException("AES-decryption failed", e);
        }
    }

    /**
     * Splits long header values into folded MIME lines according to RFC standards.
     * Ensures compatibility with email header formatting.
     *
     * @param value    The original long header string
     * @return         The folded (multi-line) version of the header
     */
    public static String foldHeaderValue(String value) {
        StringBuilder folded = new StringBuilder();
        int maxLineLength = 76;  // Standard MIME line length limit
        for (int i = 0; i < value.length(); i += maxLineLength) {
            int end = Math.min(i + maxLineLength, value.length());
            folded.append(value, i, end);


            // If not at the end, add a folded line break (CRLF followed by space)
            if (end < value.length()) {
                folded.append("\r\n "); // MIME-Continuation
            }
        }
        return folded.toString();
    }
}
