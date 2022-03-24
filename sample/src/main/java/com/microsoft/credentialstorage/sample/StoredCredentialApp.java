// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.sample;

import com.microsoft.credentialstorage.model.StoredCredential;
import com.microsoft.credentialstorage.SecretStore;
import com.microsoft.credentialstorage.StorageProvider;
import com.microsoft.credentialstorage.StorageProvider.SecureOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class StoredCredentialApp {
    private static final Logger log = LoggerFactory.getLogger(StoredCredentialApp.class);

    private static final String CREDENTIALS_KEY = "TestCredentials";

    private SecretStore<StoredCredential> credentialStorage;

    public static void main(final String[] args) {
        final StoredCredentialApp app = new StoredCredentialApp();

        app.run();
    }

    private void run() {
        // Get a secure store instance.
        credentialStorage = StorageProvider.getCredentialStorage(true, SecureOption.REQUIRED);

        if (credentialStorage == null) {
            log.error("No secure credential storage available.");
            return;
        }

        registerUser();

        userLogin();

        unregisterUser();
    }

    private void registerUser() {
        log.info("Registering a new user:");

        final StoredCredential credential = enterCredentials();

        try {
            // Save the credential to the store.
            credentialStorage.add(CREDENTIALS_KEY, credential);
            log.info("User registered.");
        } finally {
            // clear password value.
            credential.clear();
        }
    }

    private void userLogin() {
        log.info("Authenticating a user");

        final StoredCredential enteredCredential = enterCredentials();
        StoredCredential storedCredential = null;

        try {
            // Save the credential to the store.
            storedCredential = credentialStorage.get(CREDENTIALS_KEY);

            if (storedCredential.equals(enteredCredential)) {
                log.info("User logged in successfully.");
            } else {
                log.info("Authentication failed.");
            }
        } finally {
            // clear password value
            enteredCredential.clear();

            if (storedCredential != null) {
                storedCredential.clear();
            }
        }
    }

    private void unregisterUser() {
        // Remove credentials from the store.
        credentialStorage.delete(CREDENTIALS_KEY);
        log.info("User deleted.");
    }

    private StoredCredential enterCredentials() {
        // Request user name from user.
        final String userName = System.console().readLine("Enter user name: ");

        // Request password from user.
        // Using API which returns char[] to avoid creating String
        // to minimize memory footprint for secure purposes.
        final char[] password = System.console().readPassword("Enter password: ");

        final StoredCredential credential = new StoredCredential(userName, password);

        // Password value is not needed anymore, clear it now without waiting GC to remove it.
        Arrays.fill(password, (char) 0x00);

        return credential;
    }
}
