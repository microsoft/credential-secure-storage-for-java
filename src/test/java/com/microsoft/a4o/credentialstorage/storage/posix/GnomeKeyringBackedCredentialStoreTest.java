// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix;

import com.microsoft.a4o.credentialstorage.helpers.StringHelperTest;
import com.microsoft.a4o.credentialstorage.helpers.XmlHelper;
import com.microsoft.a4o.credentialstorage.secret.Credential;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

import static org.junit.Assert.assertEquals;

public class GnomeKeyringBackedCredentialStoreTest {

    GnomeKeyringBackedCredentialStore underTest;

    @Before
    public void setUp() throws Exception {
        underTest = new GnomeKeyringBackedCredentialStore();
    }

    @Test
    public void serializeDeserialize_specialChars() {
        final String username = "!@#$%^&*~";
        final String password = ":'\"/";
        final Credential cred = new Credential(username, password);
        final String serialized = underTest.serialize(cred);
        final Credential processedCred = underTest.deserialize(serialized);
        assertEquals(username, processedCred.getUsername());
        assertEquals(password, processedCred.getPassword());
    }

    @Test
    public void xmlSerialization_roundTrip() throws Exception {
        final Credential credential = new Credential("douglas.adams", "42");
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = dbf.newDocumentBuilder();
        final Document serializationDoc = builder.newDocument();

        final Element element = GnomeKeyringBackedCredentialStore.toXml(credential, serializationDoc);

        serializationDoc.appendChild(element);
        final String actualXmlString = XmlHelper.toString(serializationDoc);
        final String expectedXmlString =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" +
                        "<value>\n" +
                        "    <Password>42</Password>\n" +
                        "    <Username>douglas.adams</Username>\n" +
                        "</value>";
        StringHelperTest.assertLinesEqual(expectedXmlString, actualXmlString);

        final ByteArrayInputStream bais = new ByteArrayInputStream(actualXmlString.getBytes());
        final Document deserializationDoc = builder.parse(bais);
        final Element rootNode = deserializationDoc.getDocumentElement();

        final Credential actualCredential = GnomeKeyringBackedCredentialStore.fromXml(rootNode);

        Assert.assertEquals(credential.getUsername(), actualCredential.getUsername());
        Assert.assertEquals(credential.getPassword(), actualCredential.getPassword());
    }
}