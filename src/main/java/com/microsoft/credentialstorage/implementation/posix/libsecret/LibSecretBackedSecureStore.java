// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.libsecret;

import com.microsoft.credentialstorage.SecretStore;
import com.microsoft.credentialstorage.implementation.posix.internal.GLibInitializer;
import com.microsoft.credentialstorage.implementation.posix.internal.GLibLibrary;
import com.microsoft.credentialstorage.implementation.posix.libsecret.LibSecretLibrary.GError;
import com.microsoft.credentialstorage.model.StoredSecret;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.function.BiFunction;

import static com.microsoft.credentialstorage.implementation.posix.libsecret.LibSecretLibrary.SECRET_SEARCH_LOAD_SECRETS;
import static com.microsoft.credentialstorage.implementation.posix.libsecret.LibSecretLibrary.SECRET_SEARCH_UNLOCK;

/**
 * Base class for Linux stores via libsecret library.
 * @param <E> secret class to store
 */
public abstract class LibSecretBackedSecureStore<E extends StoredSecret> implements SecretStore<E> {
    protected static final Logger logger = LoggerFactory.getLogger(LibSecretBackedSecureStore.class);

    protected static final LibSecretLibrary INSTANCE = getLibSecretLibrary();
    protected static final LibSecretLibrary.SecretSchema SCHEMA = getPasswordSchema();

    protected static final String APP_NAME = "Credential Secure Storage (libsecret)";

    protected static final String ALLOW_UNLOCK_DEFAULT_COLLECTION = "AUTH_LIB_ALLOW_UNLOCK_DEFAULT_COLLECTION";
    protected static final String ATTRIBUTE_TYPE = "Type";
    protected static final String ATTRIBUTE_KEY = "Key";
    protected static final String ATTRIBUTE_ACCOUNT = "Account";

    /**
     * Read a secret from Libsecret using its item API to get attributes containing username.
     *
     * @param key for which a secret is associated with
     * @return secret
     */
    @Override
    public E get(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Getting {} for {}", getType(), key);

        return readSecret(key, this::create);
    }

    /**
     * Delete a secret from Libsecret.
     * @param key for which a secret is associated with
     * @return true if operation succeeded
     */
    @Override
    public boolean delete(final String key) {
        Objects.requireNonNull(key, "key cannot be null");
        logger.info("Deleting {} for {}", getType(), key);

        PointerByReference error = new PointerByReference();
        try {
            final boolean result = deleteSecret(key, error);
            return result && checkResult(error, "Could not delete secret from storage");
        } finally {
            if (error.getValue() != null) {
                GLibLibrary.INSTANCE.g_error_free(error.getValue());
            }
        }
    }

    /**
     * Libsecret is considered secure
     *
     * @return {@code true} for Libsecret
     */
    @Override
    public boolean isSecure() {
        return true;
    }

    public static boolean isSupported() {
        return isLinux() && isLibSecretSupported();
    }

    /**
     * Create a {@code Secret} from the string representation
     *
     * @param username
     *      username for the secret
     * @param secret
     *      password, oauth2 access token, or Personal Access Token
     *
     * @return a {@code Secret} from the input
     */
    protected abstract E create(String username, char[] secret);

    /**
     * Return the type of this secure store, used to match the secret in Libsecret
     *
     * @return type string representation of the secret type
     */
    protected abstract String getType();

    /**
     * Check for Libsecret support on this platform
     *
     * @return {@code true} if Libsecret library is available; {@code false} otherwise
     */
    public static boolean isLibSecretSupported() {
        try {
            if (INSTANCE != null && SCHEMA != null) {
                // If we are here that means we have loaded libsecret library
                return isSimplePasswordAPISupported() && isDefaultCollectionUnlocked();
            }
        } catch (final Throwable t) {
            logger.warn("Libsecret is not available.", t);
        }

        return false;
    }

    protected <T> T readSecret(final String key, final BiFunction<String, char[], T> mapper) {
        if (INSTANCE != null && SCHEMA != null) {
            final Pointer searchAttributesHashTable = GLibLibrary.INSTANCE.g_hash_table_new(null, null);

            final PointerByReference error = new PointerByReference();
            try {
                // set attributes to search
                GLibLibrary.INSTANCE.g_hash_table_insert(searchAttributesHashTable, getPointer(ATTRIBUTE_TYPE), getPointer(getType()));
                GLibLibrary.INSTANCE.g_hash_table_insert(searchAttributesHashTable, getPointer(ATTRIBUTE_KEY), getPointer(key));

                // find the item
                Pointer item = INSTANCE.secret_service_search_sync(null, SCHEMA,
                        searchAttributesHashTable, SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS, null, error);

                if (checkResult(error, "Could not find the item in storage.")) {
                    // iterate attribute to search username
                    while (item != null) {
                        final GLibLibrary.GList listItem = new GLibLibrary.GList(item);

                        if (listItem.data != null) {
                            T userName = getStoredSecret(listItem, mapper);
                            if (userName != null) return userName;
                        }

                        item = listItem.next;
                    }
                }
            } finally {
                if (error.getValue() != null) {
                    GLibLibrary.INSTANCE.g_error_free(error.getValue());
                }

                GLibLibrary.INSTANCE.g_hash_table_destroy(searchAttributesHashTable);
            }
        } else {
            logger.warn("Libsecret is not available.");
        }

        return null;
    }

    protected boolean writeSecret(final String key, final String account, final char[] secret, final PointerByReference error) {
        if (INSTANCE != null && SCHEMA != null) {
            return INSTANCE.secret_password_store_sync(
                    SCHEMA,
                    LibSecretLibrary.SECRET_COLLECTION_DEFAULT, // save to disk
                    key, //display name
                    new String(secret),
                    null,
                    error,
                    //attributes list
                    ATTRIBUTE_TYPE, getType(),
                    ATTRIBUTE_KEY, key,
                    ATTRIBUTE_ACCOUNT, account,
                    null
            );
        }

        logger.warn("Libsecret is not available.");
        return false;
    }

    protected boolean deleteSecret(final String key, final PointerByReference error) {
        if (INSTANCE != null && SCHEMA != null) {
            return INSTANCE.secret_password_clear_sync(
                    SCHEMA,
                    null,
                    error,
                    ATTRIBUTE_TYPE, getType(),
                    ATTRIBUTE_KEY, key,
                    null);
        }

        logger.warn("Libsecret is not available.");
        return false;
    }

    private static boolean isSimplePasswordAPISupported() {
        // Make sure libsecret supports simple password API - this check does not require
        // keyring to be unlocked first 
        logger.debug("Try access libsecret with dummy data to make sure it's accessible...");
        Pointer pPassword = null;
        try {
            final PointerByReference error = new PointerByReference();
            pPassword = INSTANCE.secret_password_lookup_sync(
                    SCHEMA,
                    null,
                    error,
                    // The following two values should not match anything, calling this method purely
                    // to determine existence of this function since we have no version information
                    ATTRIBUTE_TYPE, "NullType",
                    ATTRIBUTE_KEY, "NullKey",
                    null
            );
        } catch (UnsatisfiedLinkError error) {
            logger.warn("libsecret on this platform does not support the simple password API. " +
                    "We require libsecret-1.");

            return false;
        } finally {
            if (pPassword != null) {
                INSTANCE.secret_password_free(pPassword);
            }
        }

        return true;
    }

    private static boolean isDefaultCollectionUnlocked() {
        // Make sure it's not locked, and unlock it if user allows it (usually by popping up a dialog
        // asking for user's password

        final PointerByReference error = new PointerByReference();
        Pointer secretService = null;
        try {
            secretService = INSTANCE.secret_service_get_sync(LibSecretLibrary.SECRET_SERVICE_NONE, null, error);

            if (secretService != null && checkResult(error, "Cannot get service")) {
                final Pointer secretCollection = INSTANCE.secret_collection_for_alias_sync(secretService,
                        LibSecretLibrary.SECRET_COLLECTION_DEFAULT, LibSecretLibrary.SECRET_COLLECTION_NONE, null, error);

                if (secretCollection != null && checkResult(error, "Cannot get collection by alias")) {
                    final boolean locked = INSTANCE.secret_collection_get_locked(secretCollection);

                    if (locked) {
                        logger.info("Default collection is locked, most likely due to UI is unavailable or user logged in " +
                                "automatically without supplying a password.");

                        final boolean allowUnlock = Boolean.parseBoolean(System.getProperty(ALLOW_UNLOCK_DEFAULT_COLLECTION));
                        if (allowUnlock) {
                            final Pointer objects = GLibLibrary.INSTANCE.g_list_append(null, secretCollection);
                            final PointerByReference unlocked = new PointerByReference();

                            final int unlockedItemCount = INSTANCE.secret_service_unlock_sync(secretService, objects, null, unlocked, error);
                            return unlockedItemCount > 1 && checkResult(error, "Could not unlock collection. Libsecret collection is not available.");
                        } else {
                            logger.info("Collection is locked and unavailable, please set variable {} to " +
                                    "allow unlocking the keyring with a popup dialog.", ALLOW_UNLOCK_DEFAULT_COLLECTION);
                            return false;
                        }
                    }

                    return true;
                }
            }

            return false;
        } finally {
            if (error.getValue() != null) {
                GLibLibrary.INSTANCE.g_error_free(error.getValue());
            }

            if (secretService != null) {
                INSTANCE.g_object_unref(secretService);
            }
        }
    }

    private static boolean isLibSecretLibraryAvailable() {
        if (isLinux()) {
            try {
                // First make sure Libsecret library exists
                LibSecretLibrary ignored = LibSecretLibrary.INSTANCE;

                // Try set the application name to avoid warnings while we initialize -- if this fails,
                // it's okay, it is not end of the world but user will see some warnings printed on screen
                try {
                    GLibInitializer.getInstance().initialize(APP_NAME);
                } catch (final UnsatisfiedLinkError error) {
                    logger.warn("Glib not available -- user will see warnings printed on screen. Those warnings are " +
                            "not serious and can be ignored.");
                }

                return true;
            } catch (final Throwable t) {
                // ignore error
                logger.info("libsecret library not loaded", t);
            }
        }

        return false;
    }

    private static <T> T getStoredSecret(final GLibLibrary.GList listItem, final BiFunction<String, char[], T> mapper) {
        // get attributes for secret item
        final Pointer attributesHashTable = INSTANCE.secret_item_get_attributes(listItem.data);

        try {
            // search attribute "Account"
            final Pointer userNameValue = GLibLibrary.INSTANCE.g_hash_table_lookup(attributesHashTable, getPointer(ATTRIBUTE_ACCOUNT));
            if (userNameValue != null) {
                // get secret from the secret item
                final Pointer secretValue = INSTANCE.secret_item_get_secret(listItem.data);
                if (secretValue != null) {
                    try {
                        // get secret value as text
                        final String secretValueText = INSTANCE.secret_value_get_text(secretValue);
                        if (secretValueText != null) {
                            // now we have username and password
                            final String userName = userNameValue.getString(0);
                            final char[] password = secretValueText.toCharArray();
                            return mapper.apply(userName, password);
                        }
                    } finally {
                        INSTANCE.secret_value_unref(secretValue);
                    }
                }
            }
        } finally {
            GLibLibrary.INSTANCE.g_hash_table_unref(attributesHashTable);
        }

        return null;
    }

    private static Pointer getPointer(final String str) {
        final Pointer attrTypeKey = new Memory(str.length() + 1);
        attrTypeKey.setString(0, str);
        return attrTypeKey;
    }


    private static LibSecretLibrary getLibSecretLibrary() {
        return isLibSecretLibraryAvailable() ? LibSecretLibrary.INSTANCE : null;
    }

    private static LibSecretLibrary.SecretSchema getPasswordSchema() {
        try {
            if (isLibSecretLibraryAvailable()) {
                logger.info("libsecret library loaded, creating a password SCHEMA");
                LibSecretLibrary.SecretSchema schema
                        = new LibSecretLibrary.SecretSchema();

                schema.name = APP_NAME;
                schema.flags = LibSecretLibrary.SECRET_SCHEMA_NONE;
                //Type and Key, all fields are strings
                schema.attributes = new LibSecretLibrary.SecretSchemaAttribute[4];
                schema.attributes[0] = new LibSecretLibrary.SecretSchemaAttribute();
                schema.attributes[0].name = ATTRIBUTE_TYPE;
                schema.attributes[0].type = LibSecretLibrary.SECRET_SCHEMA_ATTRIBUTE_STRING;

                schema.attributes[1] = new LibSecretLibrary.SecretSchemaAttribute();
                schema.attributes[1].name = ATTRIBUTE_KEY;
                schema.attributes[1].type = LibSecretLibrary.SECRET_SCHEMA_ATTRIBUTE_STRING;

                schema.attributes[2] = new LibSecretLibrary.SecretSchemaAttribute();
                schema.attributes[2].name = ATTRIBUTE_ACCOUNT;
                schema.attributes[2].type = LibSecretLibrary.SECRET_SCHEMA_ATTRIBUTE_STRING;

                // Terminating
                schema.attributes[3] = new LibSecretLibrary.SecretSchemaAttribute();
                schema.attributes[3].name = null;
                schema.attributes[3].type = 0;

                return schema;

            } else {
                logger.info("libsecret library not loaded, return null for SCHEMA");
            }
        } catch (final Throwable t) {
            logger.warn("creating SCHEMA failed, return null for SCHEMA.", t);
        }

        return null;
    }

    private static boolean isLinux() {
        return System.getProperty("os.name").equals("Linux");
    }

    protected static boolean checkResult(final PointerByReference error, final String message) {
        if (error.getValue() != null) {
            GError gError = Structure.newInstance(GError.class, error.getValue());
            gError.read();

            logger.error(message + ": domain: {}, code: {}, description: {}", gError.domain, gError.code, gError.message);
            return false;
        }

        return true;
    }
}
