// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.sample;

import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenType;
import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.microsoft.a4o.credentialstorage.storage.StorageProvider;
import com.microsoft.a4o.credentialstorage.storage.StorageProvider.SecureOption;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class AppToken {
    private static final String TOKEN_KEY = "TestToken";
    private static final BufferedReader INPUT = new BufferedReader(new InputStreamReader(System.in));

    public static void main(String[] args) throws IOException {
        // Get a secure store instance
        final SecretStore<Token> tokenStorage = StorageProvider.getTokenStorage(true, SecureOption.MUST);

        // Get token name from the user
        String tokenName = getTokenName();

        // Retrieve the existing token from the store
        Token storedToken = tokenStorage.get(tokenName);
        printToken(tokenName, storedToken);

        // Create a new token instance from user input
        System.out.println("Enter token value: ");
        String tokenValue = INPUT.readLine();
        Token token = new Token(tokenValue, TokenType.Personal);

        // Save the token to the store
        tokenStorage.add(tokenName, token);

        System.out.println("Added/Updated token under the key: " + tokenName);
        System.out.println();

        // Retrieve new token from the store
        Token newStoredToken = tokenStorage.get(tokenName);

        System.out.println("Retrieved the updated token using the key: " + tokenName);
        printToken(tokenName, newStoredToken);

        // Remove token from the store
        System.out.println("Remove the token under the key " + tokenName + " [Y/n]?");
        if (!"n".equalsIgnoreCase(INPUT.readLine())) {
            tokenStorage.delete(tokenName);
        }
    }

    private static void printToken(String tokenName, Token storedToken) {
        if (storedToken != null) {
            System.out.println("Retrieved the existing token using the key: " + tokenName);
            System.out.println("  Token: " + storedToken.getValue() + " (Type: " + storedToken.getType() + ")");
        } else {
            System.out.println("No stored token under the key: " + tokenName);
        }
        System.out.println();
    }

    private static String getTokenName() throws IOException {
        System.out.print("Enter token name [" + TOKEN_KEY + "]: ");
        String tokenName = INPUT.readLine();
        if (tokenName == null || tokenName.isEmpty()) tokenName = TOKEN_KEY;
        return tokenName;
    }
}
