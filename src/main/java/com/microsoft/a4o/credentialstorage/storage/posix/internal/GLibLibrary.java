// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix.internal;

import com.sun.jna.Library;
import com.sun.jna.Native;

/**
 * Only expose one method to set application name to suppress
 * warning: "g_set_application_name not set"
 */
public interface GLibLibrary extends Library {
    GLibLibrary INSTANCE = Native.load("glib-2.0", GLibLibrary.class);

    void g_set_application_name(final String application_name);
}
