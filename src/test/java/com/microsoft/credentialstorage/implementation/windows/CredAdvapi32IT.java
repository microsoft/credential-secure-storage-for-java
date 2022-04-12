// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.windows;

import com.sun.jna.LastErrorException;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.ptr.IntByReference;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class CredAdvapi32IT {

    @Before
    public void setUp() {
        assumeTrue(CredManagerBackedSecureStore.isSupported());
    }

    // Attributes of the credential object for asserting
    private static final String KEY = "java-auth-test:https://test.com:token";
    private static final String PAT = "Personal Access Token";
    private static final String COMMENT = "Testing CredAdvapi32 instance";

    @Test
    public void e2eTest() {
        CredAdvapi32 instance = CredAdvapi32.INSTANCE;

        // make sure we can coexist with Advapi32 Instance since we load the same dll
        String username = callAdvapi32ForUsername();
        assertNotNull("Failed to retrieve username from Advapi32", username);

        // Now let's write a credential to Credential Manager
        String password = UUID.randomUUID().toString();
        CredAdvapi32.CREDENTIAL credential = buildCred(KEY, username, password);

        // TESTING CredWrite
        boolean written = instance.CredWrite(credential, 0);

        assertTrue("Failed to write to Windows Credential Manager.", written);

        // Now let's read it out again and make sure we got correct values back
        // TESTING CredRead
        CredAdvapi32.PCREDENTIAL pcredential = new CredAdvapi32.PCREDENTIAL();
        boolean read = instance.CredRead(KEY, CredAdvapi32.CRED_TYPE_GENERIC, 0, pcredential);

        assertTrue("Could not read the credential from Windows Credential Manager", read);

        CredAdvapi32.CREDENTIAL readCredential = new CredAdvapi32.CREDENTIAL(pcredential.credential);
        assertEquals("TargetName not correct", KEY, readCredential.TargetName);
        assertEquals("Type not correct", CredAdvapi32.CRED_TYPE_GENERIC, readCredential.Type);
        assertEquals("Comment not correct", COMMENT, readCredential.Comment);
        assertEquals("Persist not correct", CredAdvapi32.CRED_PERSIST_LOCAL_MACHINE, readCredential.Persist);

        // credentials
        assertEquals("Username not correct", username, readCredential.UserName);
        // First way to read a string
        byte[] passwordInBytes = readCredential.CredentialBlob.getByteArray(0, readCredential.CredentialBlobSize);
        assertEquals("Credential not correct", password, new String(passwordInBytes, StandardCharsets.UTF_8));

        // Another way to read string (without charset info, so I prefer the first method)
        assertEquals("Attribute Type not correct", PAT, readCredential.Attributes.Value.getString(0));

        // TESTING CredFree -- Need to free the memory
        instance.CredFree(pcredential.credential);

        // TESTING CredDelete
        boolean deleted = instance.CredDelete(KEY, CredAdvapi32.CRED_TYPE_GENERIC, 0);

        assertTrue("Credential not deleted, ", deleted);

        // Now read this cred again should throw LastErrorException, but since we
        // can't expect that exception (otherwise we don't know if it failed before), let's wrap it
        // into a IllegalStateException and throw that

        boolean lastErrorExceptionThrown = false;
        try {
            // if we don't throw anything, tests will fail since it expects IllegaStateException
            instance.CredRead(KEY, CredAdvapi32.CRED_TYPE_GENERIC, 0, pcredential);
        } catch (LastErrorException e) {
            lastErrorExceptionThrown = true;
        }

        assertTrue(
            "CredRead did not throw LastErrorException even when reading non existing cred, maybe delete failed?",
            lastErrorExceptionThrown);
    }

    private String callAdvapi32ForUsername() {
        Advapi32 advapi32 = Advapi32.INSTANCE;

        IntByReference plen = new IntByReference();
        char[] buffer = new char[1024];
        plen.setValue(buffer.length);

        // make a valid advapi32 call to make sure we are fine
        advapi32.GetUserNameW(buffer, plen);
        return new String(buffer,
                0,
                plen.getValue() - 1 // remove the trailing NUL
        );
    }

    private CredAdvapi32.CREDENTIAL buildCred(String key, String username, String password) {
        CredAdvapi32.CREDENTIAL credential = new CredAdvapi32.CREDENTIAL();

        // Populate credential struct
        credential.Flags = 0;
        credential.Type = CredAdvapi32.CRED_TYPE_GENERIC;
        credential.TargetName = key;
        credential.Comment = COMMENT;

        byte[] pass = password.getBytes(StandardCharsets.UTF_8);

        credential.CredentialBlobSize = pass.length;
        credential.CredentialBlob = getPointer(pass);

        credential.Persist = CredAdvapi32.CRED_PERSIST_LOCAL_MACHINE;
        credential.UserName = username;

        setAttribute(credential);

        return credential;
    }

    private Pointer getPointer(byte[] array) {
        Pointer p = new Memory(array.length);
        p.write(0, array, 0, array.length);

        return p;
    }

    private void setAttribute(CredAdvapi32.CREDENTIAL credential) {
        credential.AttributeCount = 1;

        CredAdvapi32.CREDENTIAL_ATTRIBUTE.ByReference attrByRef = new CredAdvapi32.CREDENTIAL_ATTRIBUTE.ByReference();
        attrByRef.Flags = 0;
        attrByRef.Keyword = "Credential Type";
        byte[] value = PAT.getBytes(StandardCharsets.UTF_8);
        attrByRef.ValueSize = value.length;
        attrByRef.Value = getPointer(value);

        credential.Attributes = attrByRef;
    }

}