package com.fsck.k9.ui.settings.account.pqcExtension.benchmark;

import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
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
import org.bouncycastle.openpgp.PGPSignatureVerifier;
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
            runClassicPgpSignatureOnly(context);
            runHybridSignature(context);
            runHybridEncryptionWithAesVariants(context);
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
            "Algorithm","Iter", "KG_ns","KG_mem", "Sign_ns","Sign_mem","Sig_bytes",
            "Ver_ns","Ver_mem", "PubKey_bytes","PrivKey_bytes","Valid"
        });
        Set<String> blacklist = new HashSet<>(Arrays.asList("cross-rsdp-256-small"));
        Runtime rt = Runtime.getRuntime();
        for (String alg : algorithms) {
            if (blacklist.contains(alg)) continue;
            Signature signer = new Signature(alg);
            Timber.d("Aktueller algorithmus:" + alg);

            for (int i = 0; i < ITERATIONS; i++) {

                long beforeMem = rt.totalMemory() - rt.freeMemory();
                long t0 = System.nanoTime();
                signer.generate_keypair();
                long t1 = System.nanoTime();
                long afterMem = rt.totalMemory() - rt.freeMemory();
                long kgMem = afterMem - beforeMem;

                byte[] pub = signer.export_public_key();
                byte[] priv = signer.export_secret_key();
                int pubSz = pub.length;
                int privSz = priv.length;

                beforeMem = rt.totalMemory() - rt.freeMemory();
                long t2 = System.nanoTime();
                byte[] sig = signer.sign(SAMPLE_MESSAGE);
                long t3 = System.nanoTime();
                afterMem = rt.totalMemory() - rt.freeMemory();
                long signMem = afterMem - beforeMem;
                int sigSz = sig.length;

                beforeMem = rt.totalMemory() - rt.freeMemory();
                long t4 = System.nanoTime();
                boolean valid = signer.verify(SAMPLE_MESSAGE, sig, pub);
                long t5 = System.nanoTime();
                afterMem = rt.totalMemory() - rt.freeMemory();
                long verMem = afterMem - beforeMem;

                writer.append(String.format(Locale.US,
                    "%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%b\n",
                    alg, i,
                    t1 - t0, kgMem,
                    t3 - t2, signMem, sigSz,
                    t5 - t4, verMem,
                    pubSz, privSz,
                    valid
                ));
            }
            signer.dispose_sig();
        }
        writer.flush(); writer.close();
    }


    /**
     * Misst die Performance klassischer PGP-Signaturen (RSA 2048) zur Vergleichbarkeit mit PQC-Verfahren.
     * Enthält: Zeitmessung für KeyGen, Signaturerstellung und -verifikation, Speichernutzung, Signaturgröße.
     *
     * Ergebnisse werden in `pgp_signature_benchmark.csv` geschrieben.
     */
    private static void runClassicPgpSignatureOnly(Context context) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Writer writer = initCsv(context, "pgp_signature_benchmark.csv", new String[]{
            "Iter", "KG_ns", "KG_mem", "Sign_ns", "Sign_mem", "Sig_bytes", "Ver_ns", "Ver_mem", "Valid"
        });

        Runtime rt = Runtime.getRuntime();
        for (int i = 0; i < ITERATIONS; i++) {
            long memBefore = rt.totalMemory() - rt.freeMemory();
            long t0 = System.nanoTime();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair rsaKp = kpg.generateKeyPair();
            JcaPGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_SIGN, rsaKp, new Date());
            long t1 = System.nanoTime();
            long memAfter = rt.totalMemory() - rt.freeMemory();
            long kgMem = memAfter - memBefore;

            PGPPrivateKey pgpPriv = pgpKeyPair.getPrivateKey();
            PGPPublicKey pgpPub = pgpKeyPair.getPublicKey();

            long signMemBefore = rt.totalMemory() - rt.freeMemory();
            long signT0 = System.nanoTime();
            PGPSignatureGenerator pgpGen = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(pgpPub.getAlgorithm(), HashAlgorithmTags.SHA512).setProvider( new BouncyCastleProvider())
            );
            pgpGen.init(PGPSignature.BINARY_DOCUMENT, pgpPriv);
            pgpGen.update(SAMPLE_MESSAGE);
            ByteArrayOutputStream pgpBos = new ByteArrayOutputStream();
            PGPSignature signature = pgpGen.generate();
            try (ArmoredOutputStream aos = new ArmoredOutputStream(pgpBos)) {
                signature.encode(aos);
            }
            long signT1 = System.nanoTime();
            long signMem = (rt.totalMemory() - rt.freeMemory()) - signMemBefore;
            byte[] pgpSig = pgpBos.toByteArray();
            int sigSz = pgpSig.length;

            // Verification
            long verMemBefore = rt.totalMemory() - rt.freeMemory();
            long verT0 = System.nanoTime();
            PGPSignatureVerifier verifier = new PGPSignatureVerifier(pgpPub, signature);
            boolean valid = verifier.verify(SAMPLE_MESSAGE);
            long verT1 = System.nanoTime();
            long verMem = (rt.totalMemory() - rt.freeMemory()) - verMemBefore;

            writer.append(String.format(Locale.US,
                "%d,%d,%d,%d,%d,%d,%d,%d,%b\n",
                i, t1 - t0, kgMem,
                signT1 - signT0, signMem, sigSz,
                verT1 - verT0, verMem, valid
            ));
        }
        writer.flush(); writer.close();
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
            "Algorithm","Iter", "KG_ns","KG_mem", "Enc_ns","Enc_mem","CT_bytes","SS_bytes",
            "Dec_ns","Dec_mem","Match"
        });
        Set<String> blacklist = new HashSet<>(Arrays.asList("Classic-McEliece-6688128","Classic-McEliece-6688128f","Classic-McEliece-6960119","Classic-McEliece-6960119f","Classic-McEliece-8192128","Classic-McEliece-8192128f"));
        Runtime rt = Runtime.getRuntime();
        for (String alg : algorithms) {
            if (blacklist.contains(alg)) continue;
            Timber.d("Aktueller KEM algorithmus:" + alg);
            KeyEncapsulation kem = new KeyEncapsulation(alg);


            for (int i = 0; i < ITERATIONS; i++) {
                long beforeMem = rt.totalMemory() - rt.freeMemory();
                long t0 = System.nanoTime();
                kem.generate_keypair();
                long t1 = System.nanoTime();
                long afterMem = rt.totalMemory() - rt.freeMemory();
                long kgMem = afterMem - beforeMem;

                byte[] pub = kem.export_public_key();

                beforeMem = rt.totalMemory() - rt.freeMemory();
                long t2 = System.nanoTime();
                Pair<byte[],byte[]> pair = kem.encap_secret(pub);
                long t3 = System.nanoTime();
                afterMem = rt.totalMemory() - rt.freeMemory();
                long encMem = afterMem - beforeMem;
                byte[] ct = pair.getLeft();
                byte[] ssEnc = pair.getRight();
                int ctSz = ct.length;
                int ssSz = ssEnc.length;

                beforeMem = rt.totalMemory() - rt.freeMemory();
                long t4 = System.nanoTime();
                byte[] ssDec = kem.decap_secret(ct);
                long t5 = System.nanoTime();
                afterMem = rt.totalMemory() - rt.freeMemory();
                long decMem = afterMem - beforeMem;
                boolean match = java.util.Arrays.equals(ssEnc, ssDec);

                writer.append(String.format(Locale.US,
                    "%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%b\n",
                    alg, i,
                    t1 - t0, kgMem,
                    t3 - t2, encMem, ctSz, ssSz,
                    t5 - t4, decMem, match
                ));

            }
            kem.dispose_KEM();
        }
        writer.flush(); writer.close();
    }

    /**
     * Misst die kombinierte Signaturleistung aus klassischer PGP (RSA 2048) und post-quantum Signaturen (hybrider Modus).
     * Ziel: kombinierte Sicherheit evaluieren, Performance vergleichen.
     *
     * Erfasst: Zeit und Speicherbedarf für KeyGen, Signaturgröße, kombinierte Laufzeiten.
     * Ergebnisse werden in `hybrid_signature.csv` geschrieben.
     */
    private static void runHybridSignature(Context context) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        List<String> algorithms = Sigs.get_supported_sigs();
        Writer writer = initCsv(context, "hybrid_signature.csv", new String[]{
            "Algorithm","Iter",
            "PGP_KG_ns","PGP_KG_mem","PGP_Pub_bytes","PGP_Sec_bytes",
            "PQC_KG_ns","PQC_KG_mem","PQC_Pub_bytes","PQC_Sec_bytes",
            "PGP_Sign_ns","PGP_Sign_mem","PGP_Sig_bytes",
            "PQC_Sign_ns","PQC_Sign_mem","PQC_Sig_bytes"
        });
        Set<String> blacklist = new HashSet<>(Arrays.asList("cross-rsdp-256-small"));
        // Generate and wrap PGP keypair once, measuring both operations together
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        kpg.initialize(2048);
        Runtime rt = Runtime.getRuntime();
        long pgpMemBefore = rt.totalMemory() - rt.freeMemory();
        long pgpT0 = System.nanoTime();
        KeyPair rsaKp = kpg.generateKeyPair();
        JcaPGPKeyPair pgpKeyPair = new JcaPGPKeyPair(
            PGPPublicKey.RSA_SIGN,
            rsaKp,
            new Date()
        );
        long pgpT1 = System.nanoTime();
        long pgpMemAfter = rt.totalMemory() - rt.freeMemory();
        long pgpKgNs = pgpT1 - pgpT0;
        long pgpKgMem = pgpMemAfter - pgpMemBefore;
        PGPPrivateKey pgpPriv = pgpKeyPair.getPrivateKey();
        PGPPublicKey pgpPub = pgpKeyPair.getPublicKey();
        int pgpSecSz = pgpPriv.getPrivateKeyDataPacket().getEncoded().length;
        int pgpPubSz = pgpPub.getEncoded().length;

        for (String alg : algorithms) {
            if (blacklist.contains(alg)) continue;
            // Generate PQC keypair, measuring together
            long pqcMemBefore = rt.totalMemory() - rt.freeMemory();
            long pqcT0 = System.nanoTime();
            Signature pqcSigner = new Signature(alg);
            pqcSigner.generate_keypair();
            long pqcT1 = System.nanoTime();
            long pqcMemAfter = rt.totalMemory() - rt.freeMemory();
            long pqcKgNs = pqcT1 - pqcT0;
            long pqcKgMem = pqcMemAfter - pqcMemBefore;
            byte[] pqcPub = pqcSigner.export_public_key();
            byte[] pqcSec = pqcSigner.export_secret_key();
            int pqcPubSz = pqcPub.length;
            int pqcSecSz = pqcSec.length;

            for (int i = 0; i < ITERATIONS; i++) {
                // PGP signing once per iteration
                long signMemBefore = rt.totalMemory() - rt.freeMemory();
                long signT0 = System.nanoTime();
                PGPSignatureGenerator pgpGen = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(
                        pgpPub.getAlgorithm(), HashAlgorithmTags.SHA512
                    ).setProvider( new BouncyCastleProvider())
                );
                pgpGen.init(PGPSignature.BINARY_DOCUMENT, pgpPriv);
                pgpGen.update(SAMPLE_MESSAGE);
                ByteArrayOutputStream pgpBos = new ByteArrayOutputStream();
                try (ArmoredOutputStream aos = new ArmoredOutputStream(pgpBos)) {
                    pgpGen.generate().encode(aos);
                }
                long signT1 = System.nanoTime();
                long pgpSignMem = (rt.totalMemory() - rt.freeMemory()) - signMemBefore;
                byte[] pgpSig = pgpBos.toByteArray();
                int pgpSigSz = pgpSig.length;

                // PQC signing
                signMemBefore = rt.totalMemory() - rt.freeMemory();
                long pqcSignT0 = System.nanoTime();
                byte[] pqcSig = pqcSigner.sign(SAMPLE_MESSAGE);
                long pqcSignT1 = System.nanoTime();
                long pqcSignMem = (rt.totalMemory() - rt.freeMemory()) - signMemBefore;
                int pqcSigSz = pqcSig.length;

                writer.append(String.format(Locale.US,
                    "%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
                    alg, i,
                    pgpKgNs, pgpKgMem, pgpPubSz, pgpSecSz,
                    pqcKgNs, pqcKgMem, pqcPubSz, pqcSecSz,
                    signT1 - signT0, pgpSignMem, pgpSigSz,
                    pqcSignT1 - pqcSignT0, pqcSignMem, pqcSigSz
                ));
            }
            pqcSigner.dispose_sig();
        }
        writer.flush(); writer.close();
    }

    /**
     * Führt Benchmarks für hybride Verschlüsselung durch: Kombination von PQC-KEM (z. B. Kyber) und AES-GCM.
     * Variiert dabei AES-Schlüssellängen (128, 192, 256 Bit) für differenzierte Analyse.
     *
     * Misst: KEM- und AES-Zeiten, Speicherverbrauch, Chiffretext-Größen, Übereinstimmung der geteilten Geheimnisse.
     * Ergebnisse werden in `hybrid_encryption_aes_variants.csv` geschrieben.
     */
    private static void runHybridEncryptionWithAesVariants(Context context) throws Exception {
        List<String> algorithms = KEMs.get_supported_KEMs();
        Writer writer = initCsv(context, "hybrid_encryption_aes_variants.csv", new String[]{
            "Algorithm", "Iter", "AES_KeyBits",
            "KEM_KG_ns", "KEM_KG_mem", "KEM_Pub_bytes", "KEM_Sec_bytes",
            "Enc_ns", "Enc_mem", "CT_bytes",
            "Dec_ns", "Dec_mem", "Match",
            "AES_Enc_ns", "AES_Enc_mem", "AES_CT_bytes",
            "AES_Dec_ns", "AES_Dec_mem"
        });
        Set<String> blacklist = new HashSet<>(Arrays.asList(
            "Classic-McEliece-6688128", "Classic-McEliece-6688128f",
            "Classic-McEliece-6960119", "Classic-McEliece-6960119f",
            "Classic-McEliece-8192128", "Classic-McEliece-8192128f"
        ));
        Runtime rt = Runtime.getRuntime();
        for (String alg : algorithms) {
            if (blacklist.contains(alg)) continue;
            long beforeMem = rt.totalMemory() - rt.freeMemory();
            long k0 = System.nanoTime();
            KeyEncapsulation kem = new KeyEncapsulation(alg);
            kem.generate_keypair();
            long k1 = System.nanoTime();
            long afterMem = rt.totalMemory() - rt.freeMemory();
            long kemKgMem = afterMem - beforeMem;
            byte[] kemPub = kem.export_public_key(), kemSec = kem.export_secret_key();
            int kemPubSz = kemPub.length, kemSecSz = kemSec.length;

            for (int i = 0; i < ITERATIONS; i++) {
                Pair<byte[], byte[]> p = kem.encap_secret(kemPub);
                byte[] ct = p.getLeft(), ssEnc = p.getRight();
                long e0 = System.nanoTime();
                long encMem = rt.totalMemory() - rt.freeMemory();
                long e1 = System.nanoTime();

                long d0 = System.nanoTime();
                byte[] ssDec = kem.decap_secret(ct);
                long d1 = System.nanoTime();
                long decMem = rt.totalMemory() - rt.freeMemory();
                boolean match = Arrays.equals(ssEnc, ssDec);

                for (int keyBits : new int[]{128, 192, 256}) {
                    byte[] aesKey = Arrays.copyOf(deriveAesKey(ssEnc), keyBits / 8);
                    long aesEncBefore = rt.totalMemory() - rt.freeMemory();
                    long a0 = System.nanoTime();
                    byte[] aesCt = aesEncrypt(SAMPLE_MESSAGE, aesKey);
                    long a1 = System.nanoTime();
                    long aesEncMem = rt.totalMemory() - rt.freeMemory() - aesEncBefore;
                    int aesCtSz = aesCt.length;

                    long aesDecBefore = rt.totalMemory() - rt.freeMemory();
                    long b0 = System.nanoTime();
                    byte[] aesPt = aesDecrypt(aesCt, aesKey);
                    long b1 = System.nanoTime();
                    long aesDecMem = rt.totalMemory() - rt.freeMemory() - aesDecBefore;

                    writer.append(String.format(Locale.US,
                        "%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%b,%d,%d,%d,%d,%d\n",
                        alg, i, keyBits,
                        k1 - k0, kemKgMem, kemPubSz, kemSecSz,
                        e1 - e0, encMem, ct.length,
                        d1 - d0, decMem, match,
                        a1 - a0, aesEncMem, aesCtSz,
                        b1 - b0, aesDecMem
                    ));

                }
            }
            kem.dispose_KEM();
        }
        writer.flush(); writer.close();
    }

    // --- Utility methods ---

    private static byte[] deriveAesKey(byte[] secret) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(secret);
    }

    private static byte[] aesEncrypt(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key,"AES"), new GCMParameterSpec(128,iv));
        byte[] ct = c.doFinal(data);
        ByteBuffer buf = ByteBuffer.allocate(4+iv.length+ct.length);
        buf.putInt(iv.length).put(iv).put(ct);
        return buf.array();
    }

    private static byte[] aesDecrypt(byte[] enc, byte[] key) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(enc);
        int ivLen = buf.getInt(); byte[] iv=new byte[ivLen]; buf.get(iv);
        byte[] ct=new byte[buf.remaining()]; buf.get(ct);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key,"AES"), new GCMParameterSpec(128,iv));
        return c.doFinal(ct);
    }

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
