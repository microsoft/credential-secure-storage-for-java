// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix.internal;

/**
 * Singleton-instance to make sure we only initialize glib once.
 *
 * Otherwise, we may see warnings such as: g_set_application_name() called multiple times
 */
public class GLibInitializer {

    private final GLibLibrary GLIB_INSTANCE = GLibLibrary.INSTANCE;

    private boolean glibInitialized = false;

    private GLibInitializer() {
        // singleton
    }

    private static class GLibInitializerClassHolder {
        public static final GLibInitializer INSTANCE = new GLibInitializer();
    }

    public static GLibInitializer getInstance() {
        return GLibInitializerClassHolder.INSTANCE;
    }

    public synchronized void initialize() {
        if (!glibInitialized) {
            GLIB_INSTANCE.g_set_application_name("Visual Studio Team Services");
            glibInitialized = true;
        }
    }
}
