// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.sample;

import com.microsoft.a4o.credentialstorage.secret.TokenPair;
import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.microsoft.a4o.credentialstorage.storage.StorageProvider;
import com.microsoft.a4o.credentialstorage.storage.StorageProvider.SecureOption;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class AppTokenPair {
    private static final String TOKEN_PAIR_KEY = "TestTokenPair";
    private static final BufferedReader INPUT = new BufferedReader(new InputStreamReader(System.in));

    public static void main(String[] args) throws IOException {
        // Get a secure store instance
        final SecretStore<TokenPair> tokenPairStorage = StorageProvider.getTokenPairStorage(true, SecureOption.MUST);

        // Get token pair name from the user
        String tokenPairName = getTokenPairName();

        // Retrieve the existing token pair from the store
        TokenPair storedTokenPair = tokenPairStorage.get(tokenPairName);
        printTokenPair(tokenPairName, storedTokenPair);

        // Create a new token pair instance from user input
        System.out.println("Enter access token value: ");
        String accessTokenValue = INPUT.readLine();
        System.out.println("Enter refresh token value: ");
        String refreshTokenValue = INPUT.readLine();
        TokenPair tokenPair = new TokenPair(accessTokenValue, refreshTokenValue);

        // Save the token pair to the store
        tokenPairStorage.add(tokenPairName, tokenPair);

        System.out.println("Added/Updated token pair under the key: " + tokenPairName);
        System.out.println();

        // Retrieve new token pair from the store
        TokenPair newStoredTokenPair = tokenPairStorage.get(tokenPairName);

        System.out.println("Retrieved the updated token pair using the key: " + tokenPairName);
        printTokenPair(tokenPairName, newStoredTokenPair);

        // Remove token pair from the store
        System.out.println("Remove the token pair under the key " + tokenPairName + " [Y/n]?");
        if (!"n".equalsIgnoreCase(INPUT.readLine())) {
            tokenPairStorage.delete(tokenPairName);
        }
    }

    private static void printTokenPair(String tokenPairName, TokenPair storedTokenPair) {
        if (storedTokenPair != null) {
            System.out.println("Retrieved the existing token pair using the key: " + tokenPairName);
            System.out.println("  Access token: " + storedTokenPair.getAccessToken().getValue() + " (Type: " + storedTokenPair.getAccessToken().getType() + ")");
            System.out.println("  Refresh token: " + storedTokenPair.getRefreshToken().getValue() + " (Type: " + storedTokenPair.getRefreshToken().getType() + ")");
        } else {
            System.out.println("No stored token pair under the key: " + tokenPairName);
        }
        System.out.println();
    }

    private static String getTokenPairName() throws IOException {
        System.out.print("Enter token pair name [" + TOKEN_PAIR_KEY + "]: ");
        String tokenPairName = INPUT.readLine();
        if (tokenPairName == null || tokenPairName.isEmpty()) tokenPairName = TOKEN_PAIR_KEY;
        return tokenPairName;
    }
}
