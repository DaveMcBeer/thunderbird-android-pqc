package com.fsck.k9.ui.settings.account.pqcExtension.benchmark;


import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Debug;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;

import com.fsck.k9.logging.Timber;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.openquantumsafe.*;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openquantumsafe.Signature;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
public class PQCBenchmarkRunner {

    private static int ITERATIONS = 1000;

    public static void setIterations(int iters) {
        ITERATIONS = iters;
    }
    private static byte[] SAMPLE_MESSAGE;

    private static void regenerateSampleMessage() {
        SAMPLE_MESSAGE = new byte[SAMPLE_MESSAGE_SIZE];
        new SecureRandom().nextBytes(SAMPLE_MESSAGE);
    }
    private static int SAMPLE_MESSAGE_SIZE = 1024;

    public static void setSampleMessageSize(int sizeInBytes) {
        SAMPLE_MESSAGE_SIZE = sizeInBytes;
        regenerateSampleMessage();
    }
    private static long[] measureMemoryUsage(Runnable action) {
        long beforeHeap = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        long beforeNative = Debug.getNativeHeapAllocatedSize();
        action.run();
        long afterHeap = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        long afterNative = Debug.getNativeHeapAllocatedSize();
        return new long[]{afterHeap - beforeHeap, afterNative - beforeNative};
    }

    static {
        try {
            System.loadLibrary("oqs-jni");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("oqs-jni native library konnte nicht geladen werden: " + e.getMessage());
        }
    }

    /**
     * Führt alle verfügbaren Benchmark-Tests in einem Durchlauf aus.
     * Beinhaltet: PQC-Signatur, klassische PGP-Signatur, PQC-KEM, hybride Signaturverfahren,
     * sowie hybride Verschlüsselung mit AES in unterschiedlichen Schlüssellängen (128/192/256 Bit).
     *
     * @param context Android-Kontext für Dateizugriff (CSV-Dateien)
     * @return Statusmeldung nach Abschluss der Benchmarks
     */
    public static String runAllBenchmarks(Context context) {
        try {
            runPqcSignatureOnly(context);
            runPqcKemOnly(context);
            runPureJavaRsaSignatureBenchmark(context);
            return "All benchmarks completed.";
        } catch (Exception e) {
            Log.e("PQCBenchmarkRunner", "Error during benchmarks", e);
            return "Error: " + e.getMessage();
        }
    }


    /**
     * Misst die Performance von Post-Quantum Signature (PQS) Algorithmen.
     * Erfasst: Dauer für Schlüsselerzeugung, Signatur, Verifikation, Speichernutzung, Schlüssel- und Signaturgrößen.
     *
     * Ergebnisse werden in `sig_benchmark.csv` geschrieben.
     */

    private static void runPqcSignatureOnly(Context context) throws IOException {
        List<String> algorithms = Sigs.get_supported_sigs();
        Writer writer = initCsv(context, "sig_benchmark.csv", new String[]{
            "Algorithm","Iter","KG_ns","Sign_ns","Sig_bytes",
            "Ver_ns","PubKey_bytes","PrivKey_bytes","Valid"
        });
        Set<String> blacklist = new HashSet<>(Arrays.asList("cross-rsdp-256-small"));
        for (String alg : algorithms) {
            if (blacklist.contains(alg)) continue;
            Signature signer = new Signature(alg);

            for (int i = 0; i < ITERATIONS; i++) {
                long t0 = System.nanoTime();
                signer.generate_keypair();
                long t1 = System.nanoTime();

                byte[] pub = signer.export_public_key();
                byte[] priv = signer.export_secret_key();
                int pubSz = pub.length;
                int privSz = priv.length;

                long t2 = System.nanoTime();
                final byte[][] sig = new byte[1][];
                sig[0] = signer.sign(SAMPLE_MESSAGE);
                long t3 = System.nanoTime();
                int sigSz = sig[0].length;

                long t4 = System.nanoTime();
                final boolean[] valid = new boolean[1];
                valid[0] = signer.verify(SAMPLE_MESSAGE, sig[0], pub);
                long t5 = System.nanoTime();

                writer.append(String.format(Locale.US,
                    "%s,%d,%d,%d,%d,%d,%d,%d,%b\n",
                    alg, i,
                    t1 - t0,
                    t3 - t2,
                    sigSz,
                    t5 - t4,
                    pubSz, privSz,
                    valid[0]
                ));
            }
            signer.dispose_sig();
        }
        writer.flush(); writer.close();
    }


    /**
     * Misst die Performance klassischer RSA-Signaturen (RSA 4096) mit der nativen Java-Security-API.
     * Dient der direkten Vergleichbarkeit mit PQC-Verfahren, insbesondere in Bezug auf:
     * - Schlüsselgenerierungsdauer
     * - Signier- und Verifikationszeit
     * - Signaturgröße (in Bytes)
     * - Effektive Schlüsselgrößen auf Basis des RSA-Modulus (ohne ASN.1/DER-Overhead)
     *
     * Ergebnisse werden in `rsa_java_signature_benchmark.csv` gespeichert.
     */
    private static void runPureJavaRsaSignatureBenchmark(Context context) throws Exception {
        Writer writer = initCsv(context, "rsa_java_signature_benchmark.csv", new String[]{
            "Iter", "KG_ns", "Sign_ns", "Sig_bytes", "Ver_ns", "PubKey_bytes", "PrivKey_bytes", "Valid"
        });

        for (int i = 0; i < ITERATIONS; i++) {
            // Schlüsselpaar erzeugen (RSA 4096)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(4096);
            long t0 = System.nanoTime();
            KeyPair keyPair = kpg.generateKeyPair();
            long t1 = System.nanoTime();

            PublicKey pub = keyPair.getPublic();
            PrivateKey priv = keyPair.getPrivate();

            // Effektive Schlüssellängen: Modulus-Länge in Bytes (für Vergleichbarkeit mit PQC)
            int pubKeySz = ((RSAPublicKey) pub).getModulus().bitLength() / 8;
            int privKeySz = ((RSAPrivateKey) priv).getModulus().bitLength() / 8;

            // Signatur erzeugen
            java.security.Signature signer = java.security.Signature.getInstance("SHA512withRSA");
            signer.initSign(priv);
            signer.update(SAMPLE_MESSAGE);
            long signT0 = System.nanoTime();
            byte[] sig = signer.sign();
            long signT1 = System.nanoTime();

            int sigSz = sig.length;

            // Signatur verifizieren
            java.security.Signature verifier = java.security.Signature.getInstance("SHA512withRSA");
            verifier.initVerify(pub);
            verifier.update(SAMPLE_MESSAGE);
            long verT0 = System.nanoTime();
            boolean valid = verifier.verify(sig);
            long verT1 = System.nanoTime();

            writer.append(String.format(Locale.US,
                "%d,%d,%d,%d,%d,%d,%d,%b\n",
                i,
                t1 - t0,
                signT1 - signT0,
                sigSz,
                verT1 - verT0,
                pubKeySz,
                privKeySz,
                valid
            ));
        }
        writer.flush();
        writer.close();
    }


    /**
     * Benchmarkt Key Encapsulation Mechanisms (KEM) aus dem PQC-Bereich.
     * Misst: KeyGen, Encapsulation (Enc), Decapsulation (Dec), Speichernutzung und Chiffretext-Größen.
     *
     * Ergebnisse werden in `kem_benchmark.csv` geschrieben.
     */
    private static void runPqcKemOnly(Context context) throws Exception {
        List<String> algorithms = KEMs.get_supported_KEMs();
        Writer writer = initCsv(context, "kem_benchmark.csv", new String[]{
            "Algorithm","Iter","KG_ns","Enc_ns","CT_bytes","SS_bytes",
            "Dec_ns","PubKey_bytes","PrivKey_bytes","Match"
        });
        Set<String> blacklist = new HashSet<>(Arrays.asList("Classic-McEliece-6688128","Classic-McEliece-6688128f","Classic-McEliece-6960119","Classic-McEliece-6960119f","Classic-McEliece-8192128","Classic-McEliece-8192128f"));
        for (String alg : algorithms) {
            if (blacklist.contains(alg)) continue;
            KeyEncapsulation kem = new KeyEncapsulation(alg);

            for (int i = 0; i < ITERATIONS; i++) {
                long t0 = System.nanoTime();
                kem.generate_keypair();
                long t1 = System.nanoTime();

                byte[] pub = kem.export_public_key();
                int pubSize=pub.length;
                byte[] priv = kem.export_secret_key();
                int privSize = priv.length;
                final Pair<byte[], byte[]>[] pair = new Pair[1];
                long t2 = System.nanoTime();
                pair[0] = kem.encap_secret(pub);
                long t3 = System.nanoTime();

                byte[] ct = pair[0].getLeft();
                byte[] ssEnc = pair[0].getRight();
                int ctSz = ct.length;
                int ssSz = ssEnc.length;

                final byte[][] ssDec = new byte[1][];
                long t4 = System.nanoTime();
                ssDec[0] = kem.decap_secret(ct);
                long t5 = System.nanoTime();

                boolean match = java.util.Arrays.equals(ssEnc, ssDec[0]);

                writer.append(String.format(Locale.US,
                    "%s,%d,%d,%d,%d,%d,%d,%d,%d,%b\n",
                    alg, i,
                    t1 - t0,
                    t3 - t2,
                    ctSz, ssSz,
                    t5 - t4,
                    pubSize,privSize,
                    match
                ));
            }
            kem.dispose_KEM();
        }
        writer.flush(); writer.close();
    }

    // --- Utility methods ---

    private static Writer initCsv(Context ctx, String name, String[] hdr) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ContentValues v = new ContentValues();
            v.put(MediaStore.Downloads.DISPLAY_NAME, name);
            v.put(MediaStore.Downloads.MIME_TYPE, "text/csv");
            v.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/PQCBenchmarks");
            Uri uri = ctx.getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
            OutputStream os = ctx.getContentResolver().openOutputStream(uri);
            Writer w = new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));
            w.write(String.join(",",hdr)); w.write("\n"); return w;
        } else {
            File dir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),"PQCBenchmarks");
            if (!dir.exists()) dir.mkdirs();
            File f = new File(dir,name);
            Writer w = new FileWriter(f);
            w.write(String.join(",",hdr)); w.write("\n"); return w;
        }
    }

    private static class PGPSignatureVerifier {
        private final PGPPublicKey publicKey;
        private final PGPSignature signature;

        PGPSignatureVerifier(PGPPublicKey publicKey, PGPSignature signature) {
            this.publicKey = publicKey;
            this.signature = signature;
        }

        public boolean verify(byte[] message) throws Exception {
            signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider( new BouncyCastleProvider()), publicKey);
            signature.update(message);
            return signature.verify();
        }
    }
}
