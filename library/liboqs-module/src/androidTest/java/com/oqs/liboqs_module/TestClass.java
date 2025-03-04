package com.oqs.liboqs_module;

import java.util.ArrayList;

import org.junit.Test;
import org.openquantumsafe.Common;
import org.openquantumsafe.KEMs;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;
import org.openquantumsafe.Sigs;

import static org.junit.Assert.assertArrayEquals; // Import assertArrayEquals


public class TestClass {

    @Test
    public void testKyber512Encapsulation() {
        Common.loadNativeLibrary();
        KEMs kemsInstance = KEMs.get_instance();

        ArrayList<String> supportedKems = kemsInstance.get_supported_KEMs();

        System.out.println("Supported KEMs:");
        for (String kemName : supportedKems) {
            System.out.println("- " + kemName);
        }

        Sigs sigsInstance = Sigs.get_instance();
        ArrayList<String> supportedSigs = sigsInstance.get_supported_sigs();
        System.out.println("Supported Sigs:");
        for (String sigName : supportedSigs) {
            System.out.println("- " + sigName);
        }

        String kemName = "Kyber512";
        KeyEncapsulation kem = new KeyEncapsulation(kemName);
        kem.generate_keypair();
        byte[] publicKey = kem.export_public_key();
        System.out.println("Public Key: " + Common.to_hex(publicKey));
        byte[] privateKey = kem.export_secret_key();
        System.out.println("Private Key: " + Common.to_hex(privateKey));

        Pair<byte[], byte[]> encapsulationResult = kem.encap_secret(publicKey);
        byte[] ciphertext = encapsulationResult.getLeft();
        byte[]sharedSecretEncap = encapsulationResult.getRight();
        byte[] sharedSecretDecap = kem.decap_secret(ciphertext);
        System.out.println(Common.to_hex(sharedSecretEncap));
        System.out.println(Common.to_hex(sharedSecretDecap));
        assertArrayEquals(sharedSecretEncap, sharedSecretDecap);
    }
}

