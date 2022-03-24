// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.helpers;

/**
 * System utilities
 */
public final class SystemHelper {
    private final static String osName = System.getProperty("os.name");

    private SystemHelper() {
    }

    /**
     * Check if the process is running on Windows platform
     *
     * @return
     *      {@code true} if running on Windows; {@code false} otherwise
     */
    public static boolean isWindows() {
        return osName.startsWith("Windows");
    }

    /**
     * Check if it is running on Linux 
     *
     * @return
     *      {@code true} if running on Linux; {@code false} otherwise
     */
    public static boolean isLinux() {
        return osName.equals("Linux");
    }

    /**
     * Check if it is running on Mac OSX
     *
     * @return
     *      {@code true} if running on Linux; {@code false} otherwise
     */
    public static boolean isMac() {
        return osName.equals("Mac OS X");
    }
}
