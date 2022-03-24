// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.keyring;

import com.microsoft.credentialstorage.implementation.posix.internal.GLibLibrary;
import com.microsoft.credentialstorage.model.StoredSecret;
import com.microsoft.credentialstorage.SecretStore;
import com.microsoft.credentialstorage.implementation.posix.internal.GLibInitializer;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.function.BiFunction;

import static com.microsoft.credentialstorage.implementation.posix.keyring.GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_SIZE;
import static com.microsoft.credentialstorage.implementation.posix.keyring.GnomeKeyringLibrary.GNOME_KEYRING_ITEM_GENERIC_SECRET;

/**
 * Base class for GNOME Keyring stores.
 * @param <E> secret class to store
 */
public abstract class GnomeKeyringBackedSecureStore<E extends StoredSecret> implements SecretStore<E> {
    protected static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedSecureStore.class);

    protected static final GnomeKeyringLibrary INSTANCE = getGnomeKeyringLibrary();
    protected static final GnomeKeyringLibrary.GnomeKeyringPasswordSchema SCHEMA = getGnomeKeyringPasswordSchema();

    protected static final String APP_NAME = "Credential Secure Storage (keyring)";

    protected static final String ALLOW_UNLOCK_KEYRING = "AUTH_LIB_ALLOW_UNLOCK_GNOME_KEYRING";
    protected static final String ATTRIBUTE_TYPE = "Type";
    protected static final String ATTRIBUTE_KEY = "Key";
    protected static final String ATTRIBUTE_ACCOUNT = "Account";

    /**
     * Read a secret from GNOME Keyring using its item API to get attributes containing username.
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
     * Delete a secret from GNOME Keyring.
     * @param key for which a secret is associated with
     * @return true if operation succeeded
     */
    @Override
    public boolean delete(final String key) {
        Objects.requireNonNull(key, "key cannot be null");
        logger.info("Deleting {} for {}", getType(), key);

        final int result = deleteSecret(key);
        return checkResult(result, "Could not delete secret from storage");
    }

    /**
     * GNOME Keyring is considered secure
     *
     * @return {@code true} for GNOME Keyring
     */
    @Override
    public boolean isSecure() {
        return true;
    }

    public static boolean isSupported() {
        return isLinux() && isGnomeKeyringSupported();
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
     * Return the type of this secure store, used to match the secret in GNOME Keyring
     *
     * @return type string representation of the secret type
     */
    protected abstract String getType();

    /**
     * Check for GNOME Keyring support on this platform
     *
     * @return {@code true} if gnome-keyring library is available; {@code false} otherwise
     */
    private static boolean isGnomeKeyringSupported() {
        try {
            if (INSTANCE != null && SCHEMA != null) {
                // If we are here that means we have loaded gnome-keyring library
                final GnomeKeyringLibrary.PointerToPointer keyring_info = getGnomeKeyringInfoStruct();
                if (keyring_info != null) {
                    try {
                        return isSimplePasswordAPISupported() && isGnomeKeyringUnlocked(keyring_info);
                    } finally {
                        INSTANCE.gnome_keyring_info_free(keyring_info.pointer);
                    }
                }
            }
        } catch (final Throwable t) {
            logger.warn("Gnome Keyring is not available.", t);
        }

        return false;
    }

    protected <T> T readSecret(final String key, final BiFunction<String, char[], T> mapper) {
        if (INSTANCE != null && SCHEMA != null) {
            final Pointer searchAttributes = GLibLibrary.INSTANCE.g_array_new(0, 0, GNOME_KEYRING_ATTRIBUTE_SIZE);
            final Pointer[] foundList = new Pointer[1];
            try {
                // set attributes to search
                INSTANCE.gnome_keyring_attribute_list_append_string(searchAttributes, ATTRIBUTE_TYPE, getType());
                INSTANCE.gnome_keyring_attribute_list_append_string(searchAttributes, ATTRIBUTE_KEY, key);

                // find the item
                final int result = INSTANCE.gnome_keyring_find_items_sync(GNOME_KEYRING_ITEM_GENERIC_SECRET,
                        searchAttributes, foundList);

                if (checkResult(result, "Could not find the item in storage.")) {
                    if (foundList[0] != null && INSTANCE.g_list_length(foundList[0]) > 0) {
                        final GnomeKeyringLibrary.GnomeKeyringFound item = INSTANCE.g_list_nth_data(foundList[0], 0);
                        if (item != null && item.secret != null) {
                            // iterate attribute to search username
                            final GLibLibrary.GArray attrArray = new GLibLibrary.GArray(item.attributes);
                            if (attrArray.len > 0) {
                                // attrArray.data is actually array of GnomeKeyringAttribute, using dummy to convert it
                                final GnomeKeyringLibrary.GnomeKeyringAttribute dummyArray = new GnomeKeyringLibrary.GnomeKeyringAttribute(attrArray.data);
                                final GnomeKeyringLibrary.GnomeKeyringAttribute[] attrib =
                                        (GnomeKeyringLibrary.GnomeKeyringAttribute[]) dummyArray.toArray(attrArray.len);

                                for (GnomeKeyringLibrary.GnomeKeyringAttribute attr : attrib) {
                                    if (ATTRIBUTE_ACCOUNT.equals(attr.name)) {
                                        final String userName = attr.value;
                                        final char[] secret = item.secret.toCharArray();
                                        return mapper.apply(userName, secret);
                                    }
                                }
                            }
                        }
                    }
                }
            } finally {
                if (foundList[0] != null) {
                    INSTANCE.gnome_keyring_found_list_free(foundList[0]);
                }
                INSTANCE.gnome_keyring_attribute_list_free(searchAttributes);
            }
        } else {
            logger.warn("Gnome Keyring is not available.");
        }

        return null;
    }

    protected int writeSecret(final String key, final String account, final char[] secret) {
        if (INSTANCE != null && SCHEMA != null) {
            return INSTANCE.gnome_keyring_store_password_sync(
                    SCHEMA,
                    GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, // save to disk
                    key, //display name
                    new String(secret),
                    //attributes list
                    ATTRIBUTE_TYPE, getType(),
                    ATTRIBUTE_KEY, key,
                    ATTRIBUTE_ACCOUNT, account,
                    null
            );
        }

        logger.warn("Gnome Keyring is not available.");
        return GnomeKeyringLibrary.GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON;
    }

    protected int deleteSecret(final String key) {
        if (INSTANCE != null && SCHEMA != null) {
            return INSTANCE.gnome_keyring_delete_password_sync(
                    SCHEMA,
                    ATTRIBUTE_TYPE, getType(),
                    ATTRIBUTE_KEY, key,
                    null);
        }

        logger.warn("Gnome Keyring is not available.");
        return GnomeKeyringLibrary.GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON;
    }

    private static GnomeKeyringLibrary.PointerToPointer getGnomeKeyringInfoStruct() {
        // First make sure we can access gnome-keyring (ssh session may have trouble accessing gnome-keyring)     
        final GnomeKeyringLibrary.PointerToPointer keyring_info_container = new GnomeKeyringLibrary.PointerToPointer();
        final int ret  = INSTANCE.gnome_keyring_get_info_sync(
                GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, keyring_info_container);

        return checkResult(ret, "Could not get default keyring info. GNOME Keyring is not available.")
                ? keyring_info_container : null;
    }

    private static boolean isSimplePasswordAPISupported() {
        // Simple password API is introduced in v2.22.  Unfortunately there is no easy way to discover the version
        // of Gnome Keyring library

        // Make sure gnome-keyring supports simple password API - this check does not require 
        // keyring to be unlocked first 
        logger.debug("Try access gnome-keyring with dummy data to make sure it's accessible...");
        try {
            GnomeKeyringLibrary.PointerToPointer pPassword = new GnomeKeyringLibrary.PointerToPointer();
            INSTANCE.gnome_keyring_find_password_sync(
                    SCHEMA,
                    pPassword,
                    // The following two values should not match anything, calling this method purely
                    // to determine existence of this function since we have no version information
                    ATTRIBUTE_TYPE, "NullType",
                    ATTRIBUTE_KEY, "NullKey",
                    null
                    );
        } catch (UnsatisfiedLinkError error) {
            logger.warn("GNOME Keyring on this platform does not support the simple password API.  " +
                    "We require gnome-keyring 2.22+.");

            return false;
        }

        return true;
    }

    private static boolean isGnomeKeyringUnlocked(final GnomeKeyringLibrary.PointerToPointer keyring_info) {
        // Make sure it's not locked, and unlock it if user allows it (usually by popping up a dialog
        // asking for user's password
        final boolean locked = INSTANCE.gnome_keyring_info_get_is_locked(keyring_info.pointer);

        if (locked) {
            logger.info("Keyring is locked, most likely due to UI is unavailable or user logged in " +
                    "automatically without supplying a password.");

            final boolean allowUnlock = Boolean.parseBoolean(System.getProperty(ALLOW_UNLOCK_KEYRING));
            if (allowUnlock) {
                final int ret = INSTANCE.gnome_keyring_unlock_sync(GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, null);
                return checkResult(ret, "Could not unlock keyring. GNOME Keyring is not available.");
            } else {
                logger.info("Keyring is locked and unavailable, please set variable {} to " +
                        "allow unlocking the keyring with a popup dialog.", ALLOW_UNLOCK_KEYRING); 

                return false;
            }
        }

        return true;
    }

    private static boolean isGnomeKeyringLibraryAvailable() {
        if (isLinux()) {
            try {
                // First make sure gnome-keyring library exists
                GnomeKeyringLibrary ignored = GnomeKeyringLibrary.INSTANCE;

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
                logger.info("gnome-keyring library not loaded", t);
            }
        }

        return false;
    }

    private static GnomeKeyringLibrary getGnomeKeyringLibrary() {
        return isGnomeKeyringLibraryAvailable() ? GnomeKeyringLibrary.INSTANCE : null;
    }

    private static GnomeKeyringLibrary.GnomeKeyringPasswordSchema getGnomeKeyringPasswordSchema() {
        try {
            if (isGnomeKeyringLibraryAvailable()) {
                logger.info("gnome-keyring library loaded, creating a password SCHEMA");
                GnomeKeyringLibrary.GnomeKeyringPasswordSchema schema
                        = new GnomeKeyringLibrary.GnomeKeyringPasswordSchema();

                schema.item_type = GnomeKeyringLibrary.GNOME_KEYRING_ITEM_GENERIC_SECRET;
                //Type and Key, all fields are strings
                schema.attributes = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute[4];
                schema.attributes[0] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
                schema.attributes[0].name = ATTRIBUTE_TYPE;
                schema.attributes[0].type = GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;

                schema.attributes[1] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
                schema.attributes[1].name = ATTRIBUTE_KEY;
                schema.attributes[1].type = GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;

                schema.attributes[2] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
                schema.attributes[2].name = ATTRIBUTE_ACCOUNT;
                schema.attributes[2].type = GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;

                // Terminating
                schema.attributes[3] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
                schema.attributes[3].name = null;
                schema.attributes[3].type = 0;

                return schema;

            } else {
                logger.info("gnome-keyring library not loaded, return null for SCHEMA");
            }
        } catch (final Throwable t) {
            logger.warn("creating SCHEMA failed, return null for SCHEMA.", t);
        }

        return null;
    }

    private static boolean isLinux() {
        return System.getProperty("os.name").equals("Linux");
    }

    protected static boolean checkResult(final int retCode, final String message) {
        if (retCode != GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK) {
            logger.error(message);
            try {
                logger.error("Return code: {} description: {}", retCode, INSTANCE.gnome_keyring_result_to_message(retCode));
            } catch (UnsatisfiedLinkError e) {
                logger.error("Return code: {}", retCode);
            }

            return false;
        }

        return true;
    }
}
