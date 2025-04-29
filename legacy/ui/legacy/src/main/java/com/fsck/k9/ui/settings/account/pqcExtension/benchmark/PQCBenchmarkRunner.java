package com.fsck.k9.ui.settings.account.pqcExtension.benchmark;

import android.content.Context;

import org.openquantumsafe.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class PQCBenchmarkRunner {

    private static final int ITERATIONS = 1000;
    private static final byte[] SAMPLE_MESSAGE = new byte[1024];

    public static String runAllBenchmarks(Context context) {
        try {
            Common.loadNativeLibrary();
            runSignatureBenchmark(context);
            runKemBenchmark(context);
            return "Benchmark erfolgreich abgeschlossen.";
        } catch (Exception e) {
            return "Fehler beim Benchmark: " + e.getMessage();
        }
    }

    private static void runSignatureBenchmark(Context context) throws IOException {
        List<String> algorithms = Sigs.get_instance().get_supported_sigs();
        FileWriter writer = initCsv(context, "signatures.csv", new String[]{
            "Algorithm","AvgKeyGen_ms","AvgSign_ms","AvgVerify_ms","PubKey_B","SecKey_B","Sig_B","RAM_KB"
        });

        for (String alg : algorithms) {
            long totalKeygen = 0, totalSign = 0, totalVerify = 0;
            int sigSize = 0, pkSize = 0, skSize = 0;
            long totalMemory = 0;

            for (int i = 0; i < ITERATIONS; i++) {
                Runtime runtime = Runtime.getRuntime();
                runtime.gc();
                long beforeMemory = runtime.totalMemory() - runtime.freeMemory();

                long t0 = System.nanoTime();
                Signature signer = new Signature(alg);
                signer.generate_keypair();
                long t1 = System.nanoTime();
                totalKeygen += (t1 - t0);

                t0 = System.nanoTime();
                byte[] signature = signer.sign(SAMPLE_MESSAGE);
                t1 = System.nanoTime();
                totalSign += (t1 - t0);

                t0 = System.nanoTime();
                boolean valid = signer.verify(SAMPLE_MESSAGE, signature, signer.export_public_key());
                t1 = System.nanoTime();
                totalVerify += (t1 - t0);

                if (!valid) {
                    throw new RuntimeException("Signature verification failed for " + alg);
                }

                sigSize = signature.length;
                pkSize = signer.export_public_key().length;
                skSize = signer.export_secret_key().length;

                signer.dispose_sig();

                long afterMemory = runtime.totalMemory() - runtime.freeMemory();
                totalMemory += (afterMemory - beforeMemory);
            }

            writer.append(String.format("%s,%.3f,%.3f,%.3f,%d,%d,%d,%.1f\n",
                alg, toMillis(totalKeygen), toMillis(totalSign), toMillis(totalVerify),
                pkSize, skSize, sigSize, totalMemory / 1024.0 / ITERATIONS));
        }
        writer.flush();
        writer.close();
    }

    private static void runKemBenchmark(Context context) throws IOException {
        List<String> algorithms = KEMs.get_instance().get_supported_KEMs();
        FileWriter writer = initCsv(context, "kems.csv", new String[]{
            "Algorithm","AvgKeyGen_ms","AvgEncap_ms","AvgDecap_ms","PubKey_B","SecKey_B","Ciphertext_B","SharedSecret_B","RAM_KB"
        });

        for (String alg : algorithms) {
            long totalKeygen = 0, totalEncap = 0, totalDecap = 0;
            int pkSize = 0, skSize = 0, ctSize = 0, ssSize = 0;
            long totalMemory = 0;

            for (int i = 0; i < ITERATIONS; i++) {
                Runtime runtime = Runtime.getRuntime();
                runtime.gc();
                long beforeMemory = runtime.totalMemory() - runtime.freeMemory();

                long t0 = System.nanoTime();
                KeyEncapsulation kem = new KeyEncapsulation(alg);
                kem.generate_keypair();
                long t1 = System.nanoTime();
                totalKeygen += (t1 - t0);

                t0 = System.nanoTime();
                Pair<byte[], byte[]> encap = kem.encap_secret(kem.export_public_key());
                t1 = System.nanoTime();
                totalEncap += (t1 - t0);

                t0 = System.nanoTime();
                byte[] sharedSecret = kem.decap_secret(encap.getLeft());
                t1 = System.nanoTime();
                totalDecap += (t1 - t0);

                kem.dispose_KEM();

                long afterMemory = runtime.totalMemory() - runtime.freeMemory();
                totalMemory += (afterMemory - beforeMemory);

                pkSize = encap.getLeft().length;
                skSize = kem.export_secret_key().length;
                ctSize = encap.getLeft().length;
                ssSize = encap.getRight().length;
            }

            writer.append(String.format("%s,%.3f,%.3f,%.3f,%d,%d,%d,%d,%.1f\n",
                alg, toMillis(totalKeygen), toMillis(totalEncap), toMillis(totalDecap),
                pkSize, skSize, ctSize, ssSize, totalMemory / 1024.0 / ITERATIONS));
        }
        writer.flush();
        writer.close();
    }

    private static FileWriter initCsv(Context context, String name, String[] headers) throws IOException {
        File dir = new File(context.getExternalFilesDir(null), "PQCBenchmarks");
        if (!dir.exists()) dir.mkdirs();
        File csvFile = new File(dir, name);
        FileWriter writer = new FileWriter(csvFile);
        writer.append(String.join(",", headers)).append("\n");
        return writer;
    }

    private static double toMillis(long nanos) {
        return nanos / 1_000_000.0 / ITERATIONS;
    }
}
