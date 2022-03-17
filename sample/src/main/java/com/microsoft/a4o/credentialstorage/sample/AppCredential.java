// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.sample;

import com.microsoft.a4o.credentialstorage.secret.Credential;
import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.microsoft.a4o.credentialstorage.storage.StorageProvider;
import com.microsoft.a4o.credentialstorage.storage.StorageProvider.SecureOption;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class AppCredential {
    private static final String CREDENTIALS_KEY = "TestCredentials";
    private static final BufferedReader INPUT = new BufferedReader(new InputStreamReader(System.in));

    public static void main(String[] args) throws IOException {
        // Get a secure store instance
        final SecretStore<Credential> credentialStorage = StorageProvider.getCredentialStorage(true, SecureOption.MUST);

        // Get credentials name from the user
        String credentialName = getCredentialName();

        // Retrieve the existing credential from the store
        Credential storedCredential = credentialStorage.get(credentialName);
        printCredential(credentialName, storedCredential);

        // Create a new credential instance from user input
        System.out.println("Enter user name: ");
        String userName = INPUT.readLine();
        System.out.println("Enter password: ");
        String password = INPUT.readLine();
        Credential credential = new Credential(userName, password);

        // Save the credential to the store
        credentialStorage.add(credentialName, credential);

        System.out.println("Added/Updated credentials under the key: " + credentialName);
        System.out.println();

        // Retrieve the credential from the store
        Credential newStoredCredential = credentialStorage.get(credentialName);

        System.out.println("Retrieved the updated credentials using the key: " + credentialName);
        printCredential(credentialName, newStoredCredential);

        // Remove credentials from the store
        System.out.println("Remove the credentials under the key " + credentialName + " [Y/n]?");
        if (!"n".equalsIgnoreCase(INPUT.readLine())) {
            credentialStorage.delete(credentialName);
        }
    }

    private static void printCredential(String credentialName, Credential storedCredential) {
        if (storedCredential != null) {
            System.out.println("Retrieved the existing credentials using the key: " + credentialName);
            System.out.println("  Username: " + storedCredential.getUsername());
            System.out.println("  Password: " + storedCredential.getPassword());
        } else {
            System.out.println("No stored credentials under the key: " + credentialName);
        }
        System.out.println();
    }

    private static String getCredentialName() throws IOException {
        System.out.print("Enter credentials name [" + CREDENTIALS_KEY + "]: ");
        String credentialsName = INPUT.readLine();
        if (credentialsName == null || credentialsName.isEmpty()) credentialsName = CREDENTIALS_KEY;
        return credentialsName;
    }
}
