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
    }
}

