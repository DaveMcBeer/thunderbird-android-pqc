package com.fsck.k9.pqcExtension.helper.signature;

import android.content.Context;

import com.fsck.k9.pqcExtension.keyManagement.PgpSimpleKeyManager;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.json.JSONObject;
import org.openquantumsafe.Signature;

import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.util.*;

public class CompositeSignatureHelper {

    private final String userId;
    private final Context context;

    public CompositeSignatureHelper(String userId, Context context) {
        this.userId = userId;
        this.context = context;
        Security.addProvider(new BouncyCastleProvider());
    }

    public Map<String, byte[]> signAll(byte[] data) throws Exception {
        Map<String, byte[]> result = new HashMap<>();
        result.put("pgp", signWithPgp(data));
        result.put("pqc-sig", signWithPqcSig(data));
        return result;
    }

    private byte[] signWithPgp(byte[] data) throws Exception {
        String armoredPriv = context.getSharedPreferences("pgp_key_store", Context.MODE_PRIVATE)
            .getString(userId + "_priv", null);
        PGPSecretKeyRing secretKeyRing = PgpSimpleKeyManager.parseSecretKeyRing(armoredPriv);
        if (secretKeyRing == null) throw new Exception("PGP priv key missing");


        PGPSecretKey signingKey = null;
        for (PGPSecretKey key : secretKeyRing) {
            if (key.isSigningKey()) {
                signingKey = key;
                break;
            }
        }
        if (signingKey == null) throw new Exception("No signing key found in PGP key ring");

        PGPPrivateKey privateKey = signingKey.extractPrivateKey(
            new JcePBESecretKeyDecryptorBuilder()
                .setProvider(new BouncyCastleProvider())
                .build(new char[0])
        );

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(
                signingKey.getPublicKey().getAlgorithm(),
                PGPUtil.SHA512
            ).setProvider(new BouncyCastleProvider())
        );

        sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        sigGen.update(data);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ArmoredOutputStream aos = new ArmoredOutputStream(baos)) {
            sigGen.generate().encode(aos);
        }

        return baos.toByteArray();
    }

    private byte[] signWithPqcSig(byte[] data) {
        String keyJson = context.getSharedPreferences("pqc_sig_keys", Context.MODE_PRIVATE)
            .getString(userId, null);
        if (keyJson == null) {
            throw new RuntimeException("PQC private key not found");
        }

        Signature signer = null;
        try {
            JSONObject obj = new JSONObject(keyJson);
            String algorithm = obj.getString("algorithm");
            String privB64 = obj.getString("privateKey");

            byte[] privateKeyBytes = Base64.getDecoder().decode(privB64);

            signer = new Signature(algorithm, privateKeyBytes);
            return signer.sign(data);

        } catch (Exception e) {
            throw new RuntimeException("Error during PQC signature generation", e);

        } finally {
            if (signer != null) {
                signer.dispose_sig();  // ← wichtig!
            }
        }
    }


}
