// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.mpss.tests;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.system.ErrnoException;
import android.system.Os;

public final class TestRunner extends Instrumentation
{
    static
    {
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

        useCacheDirForTemporaryFiles();
        int result = runAllTests();
        Bundle results = new Bundle();
        results.putString(
            REPORT_KEY_STREAMRESULT,
            0 == result ? "\nMPSS tests passed.\n" : "\nMPSS tests failed.\n");
        finish(0 == result ? Activity.RESULT_OK : Activity.RESULT_CANCELED, results);
    }

    // Android sets TMPDIR for apps only from Android 13. Without it, std::filesystem::temp_directory_path()
    // returns /data/local/tmp, which apps cannot write.
    private void useCacheDirForTemporaryFiles()
    {
        try
        {
            Os.setenv("TMPDIR", getTargetContext().getCacheDir().getAbsolutePath(), true);
        }
        catch (ErrnoException e)
        {
            throw new IllegalStateException("Unable to set TMPDIR.", e);
        }
    }
}
