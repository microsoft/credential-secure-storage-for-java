package com.microsoft.credentialstorage.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class StoredCredentialTest {
    @Test
    public void shouldCreateCredential() {
        StoredCredential credential = new StoredCredential("test", "test_pwd".toCharArray());
        assertNotNull(credential);

        assertEquals("test", credential.getUsername());
        assertArrayEquals("test_pwd".toCharArray(), credential.getPassword());
    }

    @Test
    public void shouldCreateCredentialWithEmptyUsername() {
        StoredCredential credential = new StoredCredential("", "test_pwd".toCharArray());
        assertNotNull(credential);

        assertEquals("", credential.getUsername());
        assertArrayEquals("test_pwd".toCharArray(), credential.getPassword());
    }

    @Test
    public void shouldCreateCredentialWithEmptyPassword() {
        StoredCredential credential = new StoredCredential("test", "".toCharArray());
        assertNotNull(credential);

        assertEquals("test", credential.getUsername());
        assertArrayEquals("".toCharArray(), credential.getPassword());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotCreateCredentialWithLongUsername() {
        String userName = "a".repeat(512);
        new StoredCredential(userName, "test_pwd".toCharArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotCreateCredentialWithLongPassword() {
        String password = "a".repeat(2048);
        new StoredCredential("test", password.toCharArray());
    }

    @Test(expected = NullPointerException.class)
    public void shouldNotCreateCredentialWithNullUsername() {
        new StoredCredential(null, "test_pwd".toCharArray());
    }

    @Test(expected = NullPointerException.class)
    public void shouldNotCreateCredentialWithNullPassword() {
        new StoredCredential("test", null);
    }

    @Test
    public void shouldClearPassword() {
        StoredCredential credential = new StoredCredential("test", "test_pwd".toCharArray());
        assertNotNull(credential);

        assertArrayEquals("test_pwd".toCharArray(), credential.getPassword());

        credential.clear();
        assertEquals(0, credential.getPassword().length);
    }
}
