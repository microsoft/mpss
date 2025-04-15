// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.research.mpss;

import android.security.keystore.KeyProperties;
import java.security.spec.ECGenParameterSpec;

public class Utils {
    public static ECGenParameterSpec GetParamSpec(Algorithm algorithm)
    {
        switch(algorithm) {
            case secp256r1:
                return new ECGenParameterSpec("secp256r1");
            case secp384r1:
                return new ECGenParameterSpec("secp384r1");
            case secp521r1:
                return new ECGenParameterSpec("secp521r1");
            default:
                throw new IllegalArgumentException("No valid value for Algorithm");
        }
    }

    public static String GetDigest(Algorithm algorithm)
    {
        switch (algorithm) {
            case secp256r1:
                return KeyProperties.DIGEST_SHA256;
            case secp384r1:
                return KeyProperties.DIGEST_SHA384;
            case secp521r1:
                return KeyProperties.DIGEST_SHA512;
            default:
                throw new IllegalArgumentException("No valid value for Algorithm");
        }
    }
}
