package com.oqs.liboqs_module;

import android.os.Environment;
import org.junit.Test;
import org.openquantumsafe.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class TestClass {

    private static final int ITERATIONS = 1000;
    private static final byte[] SAMPLE_MESSAGE = new byte[1024]; // Dummy-Email-Inhalt mit 1 KB

    private FileWriter initCsv(String name, String[] headers) throws IOException {
        File dir = new File(Environment.getExternalStorageDirectory(), "PQCBenchmarks");
        if (!dir.exists()) dir.mkdirs();
        File csvFile = new File(dir, name);
        FileWriter writer = new FileWriter(csvFile);
        writer.append(String.join(",", headers)).append("\n");
        return writer;
    }

    @Test
    public void benchmarkSignatures() throws IOException {
        Common.loadNativeLibrary();
        List<String> algorithms = Sigs.get_instance().get_supported_sigs();
        FileWriter writer = initCsv("signatures.csv", new String[]{
            "Algorithm","AvgKeyGen_ms","AvgSign_ms","AvgVerify_ms","PubKey_B","SecKey_B","Sig_B","RAM_KB"
        });

        for (String alg : algorithms) {
            Signature signer = new Signature(alg);

            long totalKeygen = 0, totalSign = 0, totalVerify = 0;
            int sigSize = 0, pkSize = 0, skSize = 0;
            long totalMemory = 0;

            for (int i = 0; i < ITERATIONS; i++) {
                Runtime runtime = Runtime.getRuntime();
                runtime.gc();
                long beforeMemory = runtime.totalMemory() - runtime.freeMemory();

                long t0 = System.nanoTime();
                signer = new Signature(alg);
                long t1 = System.nanoTime();
                totalKeygen += (t1 - t0);

                byte[] sig;
                t0 = System.nanoTime();
                sig = signer.sign(SAMPLE_MESSAGE);
                t1 = System.nanoTime();
                totalSign += (t1 - t0);

                Signature verifier = new Signature(alg);
                t0 = System.nanoTime();
                boolean valid = verifier.verify(SAMPLE_MESSAGE, sig, signer.export_public_key());
                t1 = System.nanoTime();
                totalVerify += (t1 - t0);

                long afterMemory = runtime.totalMemory() - runtime.freeMemory();
                totalMemory += (afterMemory - beforeMemory);

                if (!valid) throw new AssertionError("Verifikation fehlgeschlagen bei: " + alg);

                sigSize = sig.length;
                pkSize = signer.export_public_key().length;
                skSize = signer.export_secret_key().length;

                signer.dispose_sig();
                verifier.dispose_sig();
            }

            writer.append(String.format("%s,%.3f,%.3f,%.3f,%d,%d,%d,%.1f\n",
                alg, toMillis(totalKeygen), toMillis(totalSign), toMillis(totalVerify),
                pkSize, skSize, sigSize, totalMemory / 1024.0 / ITERATIONS));
        }
        writer.flush();
        writer.close();
    }

    @Test
    public void benchmarkKEMs() throws IOException {
        Common.loadNativeLibrary();
        List<String> algorithms = KEMs.get_instance().get_supported_KEMs();
        FileWriter writer = initCsv("kems.csv", new String[]{
            "Algorithm","AvgKeyGen_ms","AvgEncap_ms","AvgDecap_ms","PubKey_B","SecKey_B","Ciphertext_B","SharedSecret_B","RAM_KB"
        });

        for (String alg : algorithms) {
            KeyEncapsulation kem = new KeyEncapsulation(alg);
            long totalKeygen = 0, totalEncap = 0, totalDecap = 0;
            int pkSize = 0, skSize = 0, ctSize = 0, ssSize = 0;
            long totalMemory = 0;

            for (int i = 0; i < ITERATIONS; i++) {
                Runtime runtime = Runtime.getRuntime();
                runtime.gc();
                long beforeMemory = runtime.totalMemory() - runtime.freeMemory();

                kem = new KeyEncapsulation(alg);
                long t0 = System.nanoTime();
                byte[] pk = kem.export_public_key();
                byte[] sk = kem.export_secret_key();
                long t1 = System.nanoTime();
                totalKeygen += (t1 - t0);

                t0 = System.nanoTime();
                Pair<byte[], byte[]> enc = kem.encap_secret(pk);
                t1 = System.nanoTime();
                totalEncap += (t1 - t0);

                t0 = System.nanoTime();
                byte[] ss = kem.decap_secret(enc.getLeft());
                t1 = System.nanoTime();
                totalDecap += (t1 - t0);

                long afterMemory = runtime.totalMemory() - runtime.freeMemory();
                totalMemory += (afterMemory - beforeMemory);

                pkSize = pk.length;
                skSize = sk.length;
                ctSize = enc.getLeft().length;
                ssSize = ss.length;

                kem.dispose_KEM();
            }

            writer.append(String.format("%s,%.3f,%.3f,%.3f,%d,%d,%d,%d,%.1f\n",
                alg, toMillis(totalKeygen), toMillis(totalEncap), toMillis(totalDecap),
                pkSize, skSize, ctSize, ssSize, totalMemory / 1024.0 / ITERATIONS));
        }
        writer.flush();
        writer.close();
    }

    private double toMillis(long nanos) {
        return nanos / 1_000_000.0 / ITERATIONS;
    }
}
