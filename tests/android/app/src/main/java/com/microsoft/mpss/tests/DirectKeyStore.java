// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.mpss.tests;

import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;

// Changes the Android key store without going through MPSS, as any code in the same application
// can. The native tests call these methods.
final class DirectKeyStore
{
    private DirectKeyStore()
    {
    }

    // Store a key generated outside the key store. The key store records it as imported.
    static void importKey(String alias) throws GeneralSecurityException, IOException
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.setEntry(
            alias,
            new KeyStore.PrivateKeyEntry(pair.getPrivate(), new Certificate[] {selfSigned(pair)}),
            new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_NONE)
                .build());
    }

    static void deleteEntry(String alias) throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.deleteEntry(alias);
    }

    // An imported private key must come with a certificate, and the platform has no public API
    // that builds one, so this assembles a minimal self-signed X.509 v1 certificate.
    private static Certificate selfSigned(KeyPair pair) throws GeneralSecurityException
    {
        // ecdsa-with-SHA256, 1.2.840.10045.4.3.2
        byte[] signatureAlgorithm = der(0x30, der(0x06, new byte[] {
            0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x04, 0x03, 0x02}));
        // commonName, 2.5.4.3
        byte[] name = der(0x30, der(0x31, der(0x30,
            der(0x06, new byte[] {0x55, 0x04, 0x03}),
            der(0x0c, "MPSS test".getBytes(StandardCharsets.UTF_8)))));
        byte[] validity = der(0x30,
            der(0x17, "000101000000Z".getBytes(StandardCharsets.US_ASCII)),
            der(0x17, "491231235959Z".getBytes(StandardCharsets.US_ASCII)));
        byte[] serialNumber = der(0x02, new byte[] {0x01});
        byte[] toBeSigned = der(0x30,
            serialNumber, signatureAlgorithm, name, validity, name, pair.getPublic().getEncoded());

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(toBeSigned);
        byte[] signature = signer.sign();

        // A BIT STRING begins with the count of unused bits in its last byte.
        byte[] signatureBits = new byte[1 + signature.length];
        System.arraycopy(signature, 0, signatureBits, 1, signature.length);

        byte[] certificate = der(0x30, toBeSigned, signatureAlgorithm, der(0x03, signatureBits));
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certificate));
    }

    // Encode one DER element. Nothing here reaches 64 KiB, so two length bytes are enough.
    private static byte[] der(int tag, byte[]... contents)
    {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] content : contents)
        {
            body.write(content, 0, content.length);
        }

        ByteArrayOutputStream element = new ByteArrayOutputStream();
        element.write(tag);
        int length = body.size();
        if (length < 0x80)
        {
            element.write(length);
        }
        else if (length < 0x100)
        {
            element.write(0x81);
            element.write(length);
        }
        else
        {
            element.write(0x82);
            element.write(length >> 8);
            element.write(length & 0xff);
        }
        element.write(body.toByteArray(), 0, length);
        return element.toByteArray();
    }
}
