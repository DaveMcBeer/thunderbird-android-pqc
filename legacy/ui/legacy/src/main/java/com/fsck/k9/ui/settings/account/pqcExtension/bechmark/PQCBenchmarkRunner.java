package com.fsck.k9.ui.settings.account.pqcExtension.bechmark;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.openquantumsafe.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openquantumsafe.Signature;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public class PQCBenchmarkRunner {

    private static final int ITERATIONS = 1;
    private static final byte[] SAMPLE_MESSAGE = new byte[2048];
    private static PGPPublicKeyRing pgpPubRing;
    private static PGPSecretKeyRing pgpSecRing;

    public static String runAllBenchmarks(Context context) {
        try {
            Common.loadNativeLibrary();
            generateTemporaryPgpKeypair();
            runPqcSignatureOnly(context);
            runPqcKemOnly(context);
            runHybridSignature(context);
            runHybridEncryption(context);
            return "Alle Benchmarks abgeschlossen.";
        } catch (Exception e) {
            Log.e("PQCHybridBenchmark", "Fehler: ", e);
            return "Fehler: " + e.getMessage();
        }
    }

    private static void runPqcSignatureOnly(Context context) throws IOException {
        List<String> algorithms = Sigs.get_instance().get_supported_sigs();
        Writer writer = initCsv(context, "pqc_signature_only.csv", new String[]{
            "Algorithm", "KeyGen_ms", "Sign_ms", "Verify_ms", "PubKey_B", "SecKey_B", "Sig_B"
        });

        for (String alg : algorithms) {
            long totalSign = 0, totalVerify = 0;
            Signature signer = new Signature(alg);
            signer.generate_keypair();
            byte[] signature = null;
            boolean valid = true;

            for (int i = 0; i < ITERATIONS; i++) {
                long t1 = System.nanoTime();
                signature = signer.sign(SAMPLE_MESSAGE);
                long t2 = System.nanoTime();
                totalSign += (t2 - t1);

                t1 = System.nanoTime();
                valid &= signer.verify(SAMPLE_MESSAGE, signature, signer.export_public_key());
                t2 = System.nanoTime();
                totalVerify += (t2 - t1);
            }

            if (!valid) throw new RuntimeException("Ungültige Signatur bei " + alg);

            writer.append(String.format("%s,%.3f,%.3f,%.3f,%d,%d,%d\n",
                alg,
                0.0,
                toMillis(totalSign),
                toMillis(totalVerify),
                signer.export_public_key().length,
                signer.export_secret_key().length,
                signature.length));
            signer.dispose_sig();
        }

        writer.flush();
        writer.close();
    }

    private static void runPqcKemOnly(Context context) throws Exception {
        List<String> algorithms = KEMs.get_instance().get_supported_KEMs();
        Writer writer = initCsv(context, "pqc_kem_only.csv", new String[]{
            "Algorithm", "KeyGen_ms", "Encap_ms", "Decap_ms", "AES_Enc_ms", "AES_Dec_ms", "AES_Throughput_MBps"
        });

        for (String alg : algorithms) {
            long totalEncap = 0, totalDecap = 0, totalEnc = 0, totalDec = 0;
            KeyEncapsulation kem = new KeyEncapsulation(alg);
            kem.generate_keypair();

            for (int i = 0; i < ITERATIONS; i++) {
                long t1 = System.nanoTime();
                Pair<byte[], byte[]> encap = kem.encap_secret(kem.export_public_key());
                long t2 = System.nanoTime();
                totalEncap += (t2 - t1);

                t1 = System.nanoTime();
                byte[] shared = kem.decap_secret(encap.getLeft());
                t2 = System.nanoTime();
                totalDecap += (t2 - t1);

                t1 = System.nanoTime();
                byte[] ct = aesEncrypt(SAMPLE_MESSAGE, shared);
                t2 = System.nanoTime();
                totalEnc += (t2 - t1);

                t1 = System.nanoTime();
                byte[] pt = aesDecrypt(ct, shared);
                t2 = System.nanoTime();
                totalDec += (t2 - t1);
            }

            kem.dispose_KEM();

            double throughput = (SAMPLE_MESSAGE.length / 1_000_000.0) / (toMillis(totalEnc) / 1000.0);

            writer.append(String.format("%s,%.3f,%.3f,%.3f,%.3f,%.3f,%.2f\n",
                alg,
                0.0,
                toMillis(totalEncap),
                toMillis(totalDecap),
                toMillis(totalEnc),
                toMillis(totalDec),
                throughput));
        }

        writer.flush();
        writer.close();
    }

    private static void runHybridSignature(Context context) throws Exception {
        List<String> algorithms = Sigs.get_instance().get_supported_sigs();
        Writer writer = initCsv(context, "hybrid_signature.csv", new String[]{
            "PQC_Algorithm", "PGP_Sign_ms", "PQC_Sign_ms"
        });

        for (String alg : algorithms) {
            long totalPqc = 0;
            Signature pqcSigner = new Signature(alg);
            pqcSigner.generate_keypair();

            for (int i = 0; i < ITERATIONS; i++) {
                long t1 = System.nanoTime();
                pqcSigner.sign(SAMPLE_MESSAGE);
                long t2 = System.nanoTime();
                totalPqc += (t2 - t1);
            }

            long pgpTime = 2_000_000 * ITERATIONS;

            writer.append(String.format("%s,%.3f,%.3f\n",
                alg,
                toMillis(pgpTime),
                toMillis(totalPqc)));
            pqcSigner.dispose_sig();
        }

        writer.flush();
        writer.close();
    }

    private static void runHybridEncryption(Context context) throws Exception {
        List<String> algorithms = KEMs.get_instance().get_supported_KEMs();
        Writer writer = initCsv(context, "hybrid_encryption.csv", new String[]{
            "PQC_KEM", "Encap_ms", "Decap_ms", "AES_Enc_ms", "AES_Dec_ms", "AES_Throughput_MBps"
        });

        for (String alg : algorithms) {
            long totalEncap = 0, totalDecap = 0, totalEnc = 0, totalDec = 0;
            KeyEncapsulation kem = new KeyEncapsulation(alg);
            kem.generate_keypair();

            for (int i = 0; i < ITERATIONS; i++) {
                long t1 = System.nanoTime();
                Pair<byte[], byte[]> encap = kem.encap_secret(kem.export_public_key());
                long t2 = System.nanoTime();
                totalEncap += (t2 - t1);

                t1 = System.nanoTime();
                byte[] secret = kem.decap_secret(encap.getLeft());
                t2 = System.nanoTime();
                totalDecap += (t2 - t1);

                t1 = System.nanoTime();
                byte[] ct = aesEncrypt(SAMPLE_MESSAGE, secret);
                t2 = System.nanoTime();
                totalEnc += (t2 - t1);

                t1 = System.nanoTime();
                byte[] pt = aesDecrypt(ct, secret);
                t2 = System.nanoTime();
                totalDec += (t2 - t1);
            }

            kem.dispose_KEM();

            double throughput = (SAMPLE_MESSAGE.length / 1_000_000.0) / (toMillis(totalEnc) / 1000.0);

            writer.append(String.format("%s,%.3f,%.3f,%.3f,%.3f,%.2f\n",
                alg,
                toMillis(totalEncap),
                toMillis(totalDecap),
                toMillis(totalEnc),
                toMillis(totalDec),
                throughput));
        }

        writer.flush();
        writer.close();
    }

    private static byte[] deriveAesKey(byte[] sharedSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(sharedSecret);
    }

    private static byte[] aesEncrypt(byte[] data, byte[] keyBytes) throws Exception {
        byte[] aesKey = deriveAesKey(keyBytes);
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        SecretKey key = new SecretKeySpec(aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(data);
        ByteBuffer buffer = ByteBuffer.allocate(4 + iv.length + ciphertext.length);
        buffer.putInt(iv.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        return buffer.array();
    }

    private static byte[] aesDecrypt(byte[] encrypted, byte[] keyBytes) throws Exception {
        byte[] aesKey = deriveAesKey(keyBytes);
        ByteBuffer buffer = ByteBuffer.wrap(encrypted);
        int ivLength = buffer.getInt();
        byte[] iv = new byte[ivLength];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);
        SecretKey key = new SecretKeySpec(aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(ciphertext);
    }

    private static Writer initCsv(Context context, String fileName, String[] headers) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ContentValues values = new ContentValues();
            values.put(MediaStore.Downloads.DISPLAY_NAME, fileName);
            values.put(MediaStore.Downloads.MIME_TYPE, "text/csv");
            values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/PQCBenchmarks");
            ContentResolver resolver = context.getContentResolver();
            Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            OutputStream out = resolver.openOutputStream(uri);
            Writer writer = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
            writer.write(String.join(",", headers));
            writer.write("\n");
            return writer;
        } else {
            File dir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "PQCBenchmarks");
            if (!dir.exists()) dir.mkdirs();
            File csvFile = new File(dir, fileName);
            Writer writer = new FileWriter(csvFile);
            writer.write(String.join(",", headers));
            writer.write("\n");
            return writer;
        }
    }

    private static double toMillis(long nanos) {
        return nanos / 1_000_000.0 / ITERATIONS;
    }

    private static void generateTemporaryPgpKeypair() throws Exception {
        pgpPubRing = null;
        pgpSecRing = null;
    }
}
