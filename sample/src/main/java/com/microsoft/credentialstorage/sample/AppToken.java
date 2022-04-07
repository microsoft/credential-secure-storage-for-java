// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.sample;

import com.microsoft.credentialstorage.secret.Token;
import com.microsoft.credentialstorage.secret.TokenType;
import com.microsoft.credentialstorage.storage.SecretStore;
import com.microsoft.credentialstorage.storage.StorageProvider;
import com.microsoft.credentialstorage.storage.StorageProvider.SecureOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class AppToken {
    private static final String TOKEN_KEY = "TestToken";
    private static final BufferedReader INPUT = new BufferedReader(new InputStreamReader(System.in));

    private static final Logger log = LoggerFactory.getLogger(AppToken.class);

    public static void main(final String[] args) throws IOException {
        // Get a secure store instance
        final SecretStore<Token> tokenStorage = StorageProvider.getTokenStorage(true, SecureOption.MUST);

        if (tokenStorage == null) {
            log.error("No secure token storage available.");
            return;
        }

        // Get token name from the user
        final String tokenName = getTokenName();

        // Retrieve the existing token from the store
        final Token storedToken = tokenStorage.get(tokenName);
        printToken(tokenName, storedToken);

        // Create a new token instance from user input
        log.info("Enter token value: ");
        final String tokenValue = INPUT.readLine();
        final Token token = new Token(tokenValue, TokenType.Personal);

        // Save the token to the store
        tokenStorage.add(tokenName, token);

        log.info("Added/Updated token under the key: {}", tokenName);

        // Retrieve new token from the store
        Token newStoredToken = tokenStorage.get(tokenName);

        log.info("Retrieved the updated token using the key: {}", tokenName);
        printToken(tokenName, newStoredToken);

        // Remove token from the store
        log.info("Remove the token under the key {} [Y/n]?", tokenName);
        final String userInput = INPUT.readLine();
        if (!"n".equalsIgnoreCase(userInput)) {
            tokenStorage.delete(tokenName);
        }
    }

    private static void printToken(final String tokenName, final Token token) {
        if (token != null) {
            log.info("Retrieved the existing token using the key: {}", tokenName);
            log.info("  Token: {} (Type: {})", token.getValue(), token.getType());
        } else {
            log.info("No stored token under the key: {}", tokenName);
        }
    }

    private static String getTokenName() throws IOException {
        log.info("Enter token name [{}]: ", TOKEN_KEY);
        String tokenName = INPUT.readLine();
        if (tokenName == null || tokenName.isEmpty()) tokenName = TOKEN_KEY;
        return tokenName;
    }
}
