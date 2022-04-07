// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.storage.posix.keyring;

import org.junit.Before;

public class GnomeKeyringBackedTokenStoreTest {

    GnomeKeyringBackedTokenStore underTest;

    @Before
    public void setUp() throws Exception {
        underTest = new GnomeKeyringBackedTokenStore();
    }
}