// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.internal;

/**
 * Singleton-instance to make sure we only initialize glib once.
 *
 * Otherwise, we may see warnings such as: g_set_application_name() called multiple times
 */
public final class GLibInitializer {

    private final GLibLibrary GLIB_INSTANCE = GLibLibrary.INSTANCE;

    private boolean glibInitialized = false;

    private GLibInitializer() {
        // singleton
    }

    private static class GLibInitializerClassHolder {
        public static final GLibInitializer INSTANCE = new GLibInitializer();
    }

    /**
     * Returns the singleton instance.
     * @return instance
     */
    public static GLibInitializer getInstance() {
        return GLibInitializerClassHolder.INSTANCE;
    }

    /**
     * Initialize Glib library by setting an application name that will be printed in Glib logs and error messages.
     * @param appName application name
     */
    public synchronized void initialize(final String appName) {
        if (!glibInitialized) {
            GLIB_INSTANCE.g_set_application_name(appName);
            glibInitialized = true;
        }
    }
}
