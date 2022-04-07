// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.keyring;

import org.junit.Before;

public class GnomeKeyringBackedCredentialStoreTest {

    GnomeKeyringBackedCredentialStore underTest;

    @Before
    public void setUp() throws Exception {
        underTest = new GnomeKeyringBackedCredentialStore();
    }
}