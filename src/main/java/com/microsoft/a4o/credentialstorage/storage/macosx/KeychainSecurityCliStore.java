// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.macosx;

import com.microsoft.a4o.credentialstorage.helpers.StringHelper;
import com.microsoft.a4o.credentialstorage.secret.Credential;
import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenPair;
import com.microsoft.a4o.credentialstorage.secret.TokenType;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class KeychainSecurityCliStore {

    private static final String SECURITY = "/usr/bin/security";
    private static final String DELETE_GENERIC_PASSWORD = "delete-generic-password";
    private static final String FIND_GENERIC_PASSWORD = "find-generic-password";
    private static final String ADD_GENERIC_PASSWORD = "add-generic-password";
    private static final String ACCOUNT_PARAMETER = "-a";
    private static final String ACCOUNT_METADATA = "acct";
    private static final String PASSWORD = "password";
    private static final String SERVICE_PARAMETER = "-s";
    private static final String KIND_PARAMETER = "-D";
    private static final String PASSWORD_PARAMETER = "-w";
    private static final String UPDATE_IF_ALREADY_EXISTS = "-U";
    private static final int ITEM_NOT_FOUND_EXIT_CODE = 44;
    private static final int USER_INTERACTION_NOT_ALLOWED_EXIT_CODE = 36;
    private static final String INTERACTIVE_MODE = "-i";

    private static final Function<String, String> QUOTING_PROCESSOR = str -> str.contains(" ") ? '"' + str + '"' : str;

    private static final Pattern MetadataLinePattern = Pattern.compile
            (
                    //   ^(\w+):\s"(.+)"
                    "^(\\w+):\\s\"(.+)\""
            );

    enum SecretKind {
        Credential,
        Token,
        TokenPair_Access_Token,
        TokenPair_Refresh_Token
    }

    enum AttributeParsingState {
        Spaces,
        StringKey,
        HexKey,
        BeforeType,
        Type,
        AfterType,
        BeforeValue,
        NullValue,
        StringValue,
        TimeDateValue,
        ValueFinished
    }

    protected boolean deleteByKind(final String targetName, final SecretKind kind) {
        try {
            final ProcessBuilder processBuilder = new ProcessBuilder(
                    SECURITY,
                    DELETE_GENERIC_PASSWORD,
                    SERVICE_PARAMETER, targetName,
                    KIND_PARAMETER, kind.name()
            );

            final Process process = processBuilder.start();

            // we don't care about the exit code
            process.waitFor();

            return true;
        } catch (final IOException | InterruptedException e) {
            throw new Error(e);
        }
    }

    private static Map<String, Object> parseKeychainMetaData(final String metadata) {
        final Map<String, Object> result = new HashMap<>();
        parseKeychainMetaData(metadata, result);
        return result;
    }

    private static void parseKeychainMetaData(final String metadata, final Map<String, Object> result) {
        final StringReader sr = new StringReader(metadata);
        try (BufferedReader br = new BufferedReader(sr)) {
            boolean parsingAttributes = false;
            String line;
            while ((line = br.readLine()) != null) {
                if (parsingAttributes) {
                    parseAttributeLine(line, result);
                } else {
                    if ("attributes:".equals(line)) {
                        parsingAttributes = true;
                    } else {
                        parseMetadataLine(line, result);
                    }
                }
            }
        } catch (final IOException e) {
            throw new Error(e);
        }
    }

    private static void parseMetadataLine(final String line, final Map<String, Object> destination) {
        final Matcher matcher = MetadataLinePattern.matcher(line);
        if (matcher.matches()) {
            final String key = matcher.group(1);
            final String value = matcher.group(2);
            destination.put(key, value);
        }
    }

    private static void parseAttributeLine(final String line, final Map<String, Object> destination) {
        final String template = "Undefined transition '%1$s' from %2$s.";
        final StringBuilder key = new StringBuilder();
        final StringBuilder type = new StringBuilder();
        final StringBuilder value = new StringBuilder();
        boolean isNullValue = false;
        AttributeParsingState state = AttributeParsingState.Spaces;
        for (final char c : line.toCharArray()) {
            switch (state) {
                case Spaces:
                    switch (c) {
                        case ' ':
                            break;
                        case '0':
                            state = AttributeParsingState.HexKey;
                            key.append(c);
                            break;
                        case '"':
                            state = AttributeParsingState.StringKey;
                            break;
                        default:
                            throw new Error(String.format(template, c, state));
                    }
                    break;
                case HexKey:
                    switch (c) {
                        case ' ':
                            state = AttributeParsingState.BeforeType;
                            break;
                        case 'x':
                        case '0':
                        case '1':
                        case '2':
                        case '3':
                        case '4':
                        case '5':
                        case '6':
                        case '7':
                        case '8':
                        case '9':
                        case 'A':
                        case 'B':
                        case 'C':
                        case 'D':
                        case 'E':
                        case 'F':
                            key.append(c);
                            break;
                        default:
                            throw new Error(String.format(template, c, state));
                    }
                    break;
                case StringKey:
                    if (c == '"') {
                        state = AttributeParsingState.BeforeType;
                    } else {
                        key.append(c);
                    }
                    break;
                case BeforeType:
                    if (c == '<') {
                        state = AttributeParsingState.Type;
                    } else {
                        throw new Error(String.format(template, c, state));
                    }
                    break;
                case Type:
                    if (c == '>') {
                        state = AttributeParsingState.AfterType;
                    } else {
                        type.append(c);
                    }
                    break;
                case AfterType:
                    if (c == '=') {
                        state = AttributeParsingState.BeforeValue;
                    } else {
                        throw new Error(String.format(template, c, state));
                    }
                    break;
                case BeforeValue:
                    switch (c) {
                        case '<':
                            state = AttributeParsingState.NullValue;
                            isNullValue = true;
                            value.append(c);
                            break;
                        case '0':
                            // TODO: check that type was "timedate"
                            state = AttributeParsingState.TimeDateValue;
                            value.append(c);
                            break;
                        case '"':
                            state = AttributeParsingState.StringValue;
                            break;
                        default:
                            throw new Error(String.format(template, c, state));
                    }
                    break;
                case NullValue:
                    switch (c) {
                        case '>':
                            state = AttributeParsingState.ValueFinished;
                            value.append(c);
                            break;
                        case 'N':
                        case 'U':
                        case 'L':
                            value.append(c);
                            break;
                        default:
                            throw new Error(String.format(template, c, state));
                    }
                    break;
                case StringValue:
                    // double quotes aren't escaped, so everything goes in as-is
                    value.append(c);
                    break;
                case TimeDateValue:
                    // we don't care about timedate for now, so just append as-is
                    value.append(c);
                    break;
                case ValueFinished:
                    throw new Error(String.format(template, c, state));
            }
        }
        if (isNullValue) {
            destination.put(key.toString(), null);
        } else if ("blob".equals(type.toString())) {
            final int lastCharIndex = value.length() - 1;
            value.deleteCharAt(lastCharIndex);
            destination.put(key.toString(), value.toString());
        }
        // TODO: else if ("timedate".equals(type))
        // TODO: else if ("uint32".equals(type))
        // TODO: else if ("sint32".equals(type))
    }

    private static void checkResult(final int result, final String stdOut, final String stdErr) {
        if (result != 0) {
            if (result == USER_INTERACTION_NOT_ALLOWED_EXIT_CODE) {
                throw new SecurityException("User interaction is not allowed.");
            } else {
                final String template = "%1$s exited with result %2$d.\nstdOut: %3$s\nstdErr: %4$s\n";
                final String message = String.format(template, SECURITY, result, stdOut, stdErr);
                throw new Error(message);
            }
        }
    }

    private static Map<String, Object> read(final SecretKind secretKind, final String serviceName) {
        final String stdOut, stdErr;
        try {
            final ProcessBuilder processBuilder = new ProcessBuilder(
                SECURITY,
                FIND_GENERIC_PASSWORD,
                SERVICE_PARAMETER, serviceName,
                KIND_PARAMETER, secretKind.name(),
                "-g" // "Display the password for the item found"
            );

            final Process process = processBuilder.start();

            final int result = process.waitFor();
            stdOut = readToString(process.getInputStream());
            stdErr = readToString(process.getErrorStream());
            if (result != 0 && result != ITEM_NOT_FOUND_EXIT_CODE) {
                checkResult(result, stdOut, stdErr);
            }
        } catch (final IOException | InterruptedException e) {
            throw new Error(e);
        }

        final Map<String, Object> metaData = parseKeychainMetaData(stdOut);
        parseKeychainMetaData(stdErr, metaData);

        return metaData;
    }

    public Credential readCredentials(final String targetName) {
        final Map<String, Object> metaData = read(SecretKind.Credential, targetName);

        final Credential result;
        if (metaData.size() > 0) {
            final String userName = (String) metaData.get(ACCOUNT_METADATA);
            final String password = (String) metaData.get(PASSWORD);

            result = new Credential(userName, password);
        } else {
            result = null;
        }

        return result;
    }

    public Token readToken(final String targetName) {
        final Map<String, Object> metaData = read(SecretKind.Token, targetName);

        final Token result;
        if (metaData.size() > 0) {
            final String typeName = (String) metaData.get(ACCOUNT_METADATA);
            final String password = (String) metaData.get(PASSWORD);

            result = new Token(password, TokenType.valueOf(typeName));
        } else {
            result = null;
        }

        return result;
    }

    public TokenPair readTokenPair(final String targetName) {
        String accessToken, refreshToken;

        final Map<String, Object> accessTokenMetaData = read(SecretKind.TokenPair_Access_Token, targetName);

        if (accessTokenMetaData.size() > 0) {
            accessToken = (String) accessTokenMetaData.get(PASSWORD);
        } else {
            accessToken = null;
        }

        final Map<String, Object> refreshTokenMetaData = read(SecretKind.TokenPair_Refresh_Token, targetName);

        if (refreshTokenMetaData.size() > 0) {
            refreshToken = (String) refreshTokenMetaData.get(PASSWORD);
        } else {
            refreshToken = null;
        }

        if (accessToken != null && refreshToken != null) {
            return new TokenPair(accessToken, refreshToken);
        }

        return null;
    }

    private static void write(final SecretKind secretKind, final String serviceName, final String accountName, final String password) {
        final String stdOut, stdErr;
        try {
            final ProcessBuilder addProcessBuilder = new ProcessBuilder(
                SECURITY,
                INTERACTIVE_MODE
            );
            final String[] commandParts = {
                ADD_GENERIC_PASSWORD,
                UPDATE_IF_ALREADY_EXISTS,
                ACCOUNT_PARAMETER, accountName,
                SERVICE_PARAMETER, serviceName,
                PASSWORD_PARAMETER, password,
                KIND_PARAMETER, secretKind.name()
            };
            final Process process = addProcessBuilder.start();
            final String command = StringHelper.join(" ", commandParts, 0, commandParts.length, QUOTING_PROCESSOR);

            try (final PrintWriter writer = new PrintWriter(process.getOutputStream())) {
                writer.println(command);
            }

            final int result = process.waitFor();
            stdOut = readToString(process.getInputStream());
            stdErr = readToString(process.getErrorStream());
            checkResult(result, stdOut, stdErr);
        } catch (final IOException | InterruptedException e) {
            throw new Error(e);
        }
    }

    public void writeCredential(final String targetName, final Credential credentials) {
        write(SecretKind.Credential, targetName, credentials.getUsername(), credentials.getPassword());
    }

    public void writeToken(final String targetName, final Token token) {
        writeTokenKind(targetName, SecretKind.Token, token);
    }

    private void writeTokenKind(final String targetName, final SecretKind secretKind, final Token token) {
        final String accountName = token.getType().name();
        write(secretKind, targetName, accountName, token.getValue());
    }

    public void writeTokenPair(final String targetName, final TokenPair tokenPair) {
        if (tokenPair.getAccessToken().getValue() != null) {
            writeTokenKind(targetName, SecretKind.TokenPair_Access_Token, tokenPair.getAccessToken());
        }

        if (tokenPair.getRefreshToken().getValue() != null) {
            writeTokenKind(targetName, SecretKind.TokenPair_Refresh_Token, tokenPair.getRefreshToken());
        }
    }

    private static String readToString(final InputStream stream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            final StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
                sb.append(System.getProperty("line.separator"));
            }
            return sb.toString();
        }
    }

}
