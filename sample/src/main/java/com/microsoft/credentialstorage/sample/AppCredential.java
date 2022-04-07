// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.sample;

import com.microsoft.credentialstorage.secret.Credential;
import com.microsoft.credentialstorage.storage.SecretStore;
import com.microsoft.credentialstorage.storage.StorageProvider;
import com.microsoft.credentialstorage.storage.StorageProvider.SecureOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class AppCredential {
    private static final Logger log = LoggerFactory.getLogger(AppCredential.class);

    private static final String CREDENTIALS_KEY = "TestCredentials";

    public static void main(final String[] args) {
        // Get a secure store instance
        final SecretStore<Credential> credentialStorage = StorageProvider.getCredentialStorage(true, SecureOption.MUST);

        if (credentialStorage == null) {
            log.error("No secure credential storage available.");
            return;
        }

        // Get credentials name from the user
        final String credentialName = getCredentialName();

        // Retrieve the existing credential from the store
        final Credential storedCredential = credentialStorage.get(credentialName);
        printCredential(credentialName, storedCredential);

        // Create a new credential instance from user input
        String userName = System.console().readLine("Enter user name: ");

        char[] password = System.console().readPassword("Enter password: ");

        final Credential credential = new Credential(userName, password);

        // Save the credential to the store
        credentialStorage.add(credentialName, credential);

        log.info("Added/Updated credentials under the key: {}", credentialName);

        // Retrieve the credential from the store
        Credential newStoredCredential = credentialStorage.get(credentialName);

        log.info("Retrieved the updated credentials using the key: {}", credentialName);
        printCredential(credentialName, newStoredCredential);

        // Remove credentials from the store
        log.info("Remove the credentials under the key {} [Y/n]?", credentialName);
        final String userInput = System.console().readLine();
        if (!"n".equalsIgnoreCase(userInput)) {
            credentialStorage.delete(credentialName);
        }
    }

    private static void printCredential(final String credentialName, final Credential credential) {
        if (credential != null) {
            log.info("Retrieved the existing credentials using the key: {}", credentialName);
            log.info("  Username: {}", credential.getUsername());
            log.info("  Password: {}", Arrays.toString(credential.getPassword()));
        } else {
            log.info("No stored credentials under the key: " + credentialName);
        }
    }

    private static String getCredentialName() {
        String credentialsName = System.console().readLine("Enter credentials name [%s]:", CREDENTIALS_KEY);
        if (credentialsName == null || credentialsName.isEmpty()) {
            credentialsName = CREDENTIALS_KEY;
        }
        return credentialsName;
    }
}
