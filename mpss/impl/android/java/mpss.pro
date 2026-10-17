# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# The MPSS native library finds these by name through JNI.
-keep class com.microsoft.mpss.KeyManagement {
    public static <methods>;
}
-keep enum com.microsoft.mpss.Algorithm {
    public static <fields>;
}
