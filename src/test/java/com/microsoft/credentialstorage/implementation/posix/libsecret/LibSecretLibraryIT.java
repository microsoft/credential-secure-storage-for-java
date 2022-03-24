// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.libsecret;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;
import org.junit.Before;
import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

public class LibSecretLibraryIT {

    LibSecretLibrary underTest;
    LibSecretLibrary.SecretSchema schema;

    @Before
    public void setUp() throws Exception {
        //Only test on platform that has gnome-keyring support
        assumeTrue(LibSecretBackedSecureStore.isLibSecretSupported());

        underTest = LibSecretLibrary.INSTANCE;
        schema = new LibSecretLibrary.SecretSchema();
        schema.flags = LibSecretLibrary.SECRET_SCHEMA_NONE;
        schema.attributes = getAttributes();
    }

    @Test
    public void e2e() {
        final String type = "PersonalAccessToken";

        final String password1 = "testingPassword";
        final String password2 = "testingPassword2";
        final String password3 = create8192CharLongPassword();
        final String key1 = "http://testingurl.com";
        final String key2 = "http://another.testingurl.com";
        final String key3 = "http://another.testingurl.org";

        // Write a credential to libsecret
        final PointerByReference pError = new PointerByReference();

        boolean result = underTest.secret_password_store_sync(
                schema,
                LibSecretLibrary.SECRET_COLLECTION_DEFAULT, //save to disk
                "E2E Manual Testing Secret", // display name
                password1,
                null,
                pError,
                //attributes list
                "Type", type,
                "Key", key1,
                null
                );

        assertTrue("Could not store password1: " + parseError(pError), result);

        result = underTest.secret_password_store_sync(
                schema,
                LibSecretLibrary.SECRET_COLLECTION_SESSION, //save to memory only
                "E2E Manual Testing Secret", // same display name
                password2,
                null,
                pError,
                //attributes list
                "Type", type,
                "Key", key2,
                null
        );

        assertTrue("Could not store password2: " + parseError(pError), result);

        result = underTest.secret_password_store_sync(
                schema,
                LibSecretLibrary.SECRET_COLLECTION_DEFAULT, //save to disk
                "E2E Manual Testing Secret", // same display name
                password3,
                null,
                pError,
                //attributes list
                "Type", type,
                "Key", key3,
                null
        );

        assertTrue("Could not store password3: " + parseError(pError), result);

        // It is a good thing to break after here and verify from any GUI keyring program you have to
        // confirm password2 is only saved in memory, it shouldn't appear in the default keyring; and
        // in the default keyring there are two items with identical description string

        // read out first password
        Pointer p1 = underTest.secret_password_lookup_sync(
                schema,
                null,
                pError,
                "Type", type,
                "Key", key1,
                null);

        assertNotNull(p1);
        assertNull("Could not read password1: " + parseError(pError), pError.getValue());
        assertEquals("Password1 incorrectly read", password1, p1.getString(0));

        // read out 3rd password
        Pointer p3 = underTest.secret_password_lookup_sync(
                schema,
                null,
                pError,
                "Type", type,
                "Key", key3,
                null);

        assertNotNull(p3);
        assertNull("Could not read password3: " + parseError(pError), pError.getValue());
        assertEquals("Password3 incorrectly read", password3, p3.getString(0));

        // let's clear out the pointers
        underTest.secret_password_free(p1);
        underTest.secret_password_free(p3);

        // now let's delete them all
        result = underTest.secret_password_clear_sync(schema, null, pError, "Type", type, "Key", key1, null);
        assertTrue(parseError(pError), result);
        result = underTest.secret_password_clear_sync(schema, null, pError, "Type", type, "Key", key2, null);
        assertTrue(parseError(pError), result);
        result = underTest.secret_password_clear_sync(schema, null, pError, "Type", type, "Key", key3, null);
        assertTrue(parseError(pError), result);

        // now read password1 should fail

        Pointer p1Again = underTest.secret_password_lookup_sync(
                schema,
                null,
                pError,
                "Type", type,
                "Key", key1,
                null);

        assertNull(p1Again);
        assertNull("Read password1 didn't result in no match? " + parseError(pError), pError.getValue());
        underTest.secret_password_free(p1Again);
    }

    private String parseError(final PointerByReference pError) {
        if (pError.getValue() != null) {
            LibSecretLibrary.GError gError = Structure.newInstance(LibSecretLibrary.GError.class, pError.getValue());
            gError.read();
            return "domain: " + gError.domain + ", code: " + gError.code + ", message: " + gError.message;
        }
        return "<n/a>";
    }

    private String create8192CharLongPassword() {
        Random rand = new Random();
        char[] password = new char[8192];
        for(int i = 0; i < 8192; ++i) {
            password[i] = (char)(rand.nextInt(26) + 'a');
        }

        return new String(password);
    }

    private LibSecretLibrary.SecretSchemaAttribute[] getAttributes() {
        //create a testing schema's attributes
        final LibSecretLibrary.SecretSchemaAttribute[] attributes
                            = new LibSecretLibrary.SecretSchemaAttribute[3];

        // type = token type; key = url entry with prefixes
        attributes[0] = new LibSecretLibrary.SecretSchemaAttribute();
        attributes[0].name = "Type";
        attributes[0].type = LibSecretLibrary.SECRET_SCHEMA_ATTRIBUTE_STRING;
        attributes[1] = new LibSecretLibrary.SecretSchemaAttribute();
        attributes[1].name = "Key";
        attributes[1].type = LibSecretLibrary.SECRET_SCHEMA_ATTRIBUTE_STRING;

        // terminating attribute
        attributes[2] = new LibSecretLibrary.SecretSchemaAttribute();
        attributes[2].name = null;
        attributes[2].type = 0;

        return attributes;
    }
}
