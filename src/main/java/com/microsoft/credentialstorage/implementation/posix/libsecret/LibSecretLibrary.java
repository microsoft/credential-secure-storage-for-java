// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.libsecret;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;

import java.util.Arrays;
import java.util.List;

/**
 * Simple interface to store and retrieve secrets with gnome-keyring
 *
 * https://developer.gnome.org/gnome-keyring/stable/ch01.html
 */
public interface LibSecretLibrary extends Library {

    LibSecretLibrary INSTANCE = Native.load("secret-1", LibSecretLibrary.class);

    /**
     * Save secrets to disk
     */
    String SECRET_COLLECTION_DEFAULT = "default";

    /**
     * Save secrets in memory
     */
    String SECRET_COLLECTION_SESSION = "session";

    /**
     * SecretServiceFlags:
     *   SECRET_SERVICE_NONE,
     *   SECRET_SERVICE_OPEN_SESSION,
     *   SECRET_SERVICE_LOAD_COLLECTIONS,
     */
    int SECRET_SERVICE_NONE = 0;
    int SECRET_SERVICE_OPEN_SESSION = 2;
    int SECRET_SERVICE_LOAD_COLLECTIONS = 4;

    /**
     * SecretSchemaFlags:
     *   SECRET_SCHEMA_NONE,
     *   SECRET_SCHEMA_DONT_MATCH_NAME
     */
    int SECRET_SCHEMA_NONE            = 0;
    int SECRET_SCHEMA_DONT_MATCH_NAME = 1;

    /**
     * SecretSchemaAttributeType:
     *   SECRET_SCHEMA_ATTRIBUTE_STRING,
     *   SECRET_SCHEMA_ATTRIBUTE_INTEGER,
     *   SECRET_SCHEMA_ATTRIBUTE_BOOLEAN
     */
    int SECRET_SCHEMA_ATTRIBUTE_STRING = 0;
    int SECRET_SCHEMA_ATTRIBUTE_INTEGER = 1;
    int SECRET_SCHEMA_ATTRIBUTE_BOOLEAN = 2;

    /**
     * SecretCollectionFlags:
     *   SECRET_COLLECTION_NONE
     *   SECRET_COLLECTION_LOAD_ITEMS
     */
    int SECRET_COLLECTION_NONE = 0;
    int SECRET_COLLECTION_LOAD_ITEMS = 2;

    /**
     * SecretSearchFlags:
     *   SECRET_SEARCH_NONE,
     *   SECRET_SEARCH_ALL,
     *   SECRET_SEARCH_UNLOCK,
     *   SECRET_SEARCH_LOAD_SECRETS
     */
    int SECRET_SEARCH_NONE = 0;
    int SECRET_SEARCH_ALL = 2;
    int SECRET_SEARCH_UNLOCK = 4;
    int SECRET_SEARCH_LOAD_SECRETS = 8;


    /**
     * Item Attributes — Attributes of individual keyring items.
     *
     * https://www.manpagez.com/html/libsecret-1/libsecret-1-0.18.6/libsecret-SecretSchema.php#SecretSchemaAttribute
     */
    class SecretSchemaAttribute extends Structure {

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("name", "type");
        }

        public String name;

        public int type;
    }

    /**
     * Schema for secret
     *
     * https://www.manpagez.com/html/libsecret-1/libsecret-1-0.18.6/libsecret-SecretSchema.php#SecretSchema
     */
    class SecretSchema extends Structure {

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("name", "flags", "attributes");
        }

        public String name;

        public int flags;

        public SecretSchemaAttribute[] attributes = new SecretSchemaAttribute[32];
    }

    /**
     * A error object.
     *
     * https://www.manpagez.com/html/glib/glib-2.56.0/glib-Error-Reporting.php#GError
     */
    class GError extends Structure {

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("domain", "code", "message");
        }

        public int domain;
        public int code;
        public String message;
    }

    /**
     * Storing a secret, without paraphrasing, please read:
     *
     * https://www.manpagez.com/html/libsecret-1/libsecret-1-0.18.6/libsecret-Password-storage.php#secret_password_lookup_sync
     *
     * @param schema
     *      schema for the secret
     * @param collection
     *      a collection alias
     * @param label
     *      label for the secret
     * @param password
     *      the password to store
     * @param cancellable
     *      cancellation object
     * @param error
     *      location to place an error on failure
     * @param args
     *      varargs, attributes of the secret, please read the API document
     *
     * @return
     *      return code
     */
    boolean secret_password_store_sync(SecretSchema schema,
                                       String collection,
                                       String label,
                                       String password,
                                       Pointer cancellable,
                                       PointerByReference error,
                                       Object... args);

    /**
     * Retrieving a stored secret, without paraphrasing, please read:
     *
     * https://www.manpagez.com/html/libsecret-1/libsecret-1-0.18.6/libsecret-Password-storage.php#secret_password_lookup_sync
     *
     * @param schema
     *      schema for the secret
     * @param cancellable
     *      cancellation object
     * @param error
     *      location to place an error on failure
     * @param args
     *      varargs, attributes of the secret, please read the API document
     *
     * @return
     *      return code
     */
    Pointer secret_password_lookup_sync(SecretSchema schema,
                                        Pointer cancellable,
                                        PointerByReference error,
                                        Object... args);

    /**
     * Delete a stored secret, without paraphrasing, please read:
     *
     * https://www.manpagez.com/html/libsecret-1/libsecret-1-0.18.6/libsecret-Password-storage.php#secret-password-clear-sync
     *
     * @param schema
     *      schema for the secret
     * @param cancellable
     *      cancellation object
     * @param error
     *      location to place an error on failure
     * @param args
     *      varargs, attributes of the secret, please read the API document
     *
     * @return
     *      return code
     */
    boolean secret_password_clear_sync(SecretSchema schema,
                                       Pointer cancellable,
                                       PointerByReference error,
                                       Object... args);

    /**
     * Search for items matching the attributes.
     *
     * http://www.manpagez.com/html/libsecret-1/libsecret-1-0.18.6/SecretService.php#secret-service-search-sync
     *
     * @param secret_service
     *      the secret service
     * @param schema
     *      schema for the secret
     * @param attributes
     *      search for items matching these attributes
     * @param flags
     *      search option flags
     * @param cancellable
     *      cancellation object
     * @param error
     *      location to place an error on failure
     * @return a list of items that matched the search
     */
    Pointer secret_service_search_sync(Pointer secret_service,
                                       SecretSchema schema,
                                       Pointer attributes,
                                       int flags,
                                       Pointer cancellable,
                                       PointerByReference error);

    Pointer secret_service_get_sync(int flags,
                                    Pointer cancellable,
                                    PointerByReference error);

    Pointer secret_collection_for_alias_sync(Pointer secret_service,
                                             String alias,
                                             int flags,
                                             Pointer cancellable,
                                             PointerByReference error);

    Pointer secret_item_get_attributes(Pointer secretItem);

    Pointer secret_item_get_secret(Pointer secretItem);

    String secret_value_get_text(Pointer secretValue);

    void secret_value_unref(Pointer secretValue);

    /**
     * Free the in memory secret pointer, without paraphrasing, please read:
     *
     * https://developer.gnome.org/gnome-keyring/stable/gnome-keyring-Simple-Password-Storage.html#gnome-keyring-free-password
     *
     * @param password
     *      pointer to the secret to be freed
     */
    void secret_password_free(Pointer password);

    /**
     * Get whether the collection is locked or not.
     *
     * @param secret_collection
     *      pointer to the collection
     * @return
     *      {@code true} when the keyring is locked; {@code false} otherwise.
     */
    boolean secret_collection_get_locked(Pointer secret_collection);

    /**
     * Unlock a collection, so that its contents may be accessed.  If password is null, user
     * will be prompted for password to unlock the keyring.
     *
     * @param secret_service
     *      pointer to the secret service
     * @param objects
     *      the items or collections to unlock.
     * @param cancellable
     *      cancellation object
     * @param unlocked
     *      location to place list of items or collections that were unlocked
     * @param error
     *      location to place an error on failure
     *
     * @return
     *      {@code true} when the keyring is unlocked; {@code false} otherwise.
     */
    int secret_service_unlock_sync(Pointer secret_service,
                                   Pointer objects,
                                   Pointer cancellable,
                                   PointerByReference unlocked,
                                   PointerByReference error);

    void g_object_unref(Pointer object);
}
