// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.mpss.tests;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;

public final class TestRunner extends Instrumentation
{
    static
    {
        System.loadLibrary(BuildConfig.MPSS_CORE_LIBRARY_NAME);
        System.loadLibrary("mpss_tests");
    }

    private static native int runAllTests();

    @Override
    public void onCreate(Bundle arguments)
    {
        super.onCreate(arguments);
        start();
    }

    @Override
    public void onStart()
    {
        super.onStart();

        int result = runAllTests();
        Bundle results = new Bundle();
        results.putString(
            REPORT_KEY_STREAMRESULT,
            0 == result ? "\nMPSS tests passed.\n" : "\nMPSS tests failed.\n");
        finish(0 == result ? Activity.RESULT_OK : Activity.RESULT_CANCELED, results);
    }
}
