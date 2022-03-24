// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix;

import com.microsoft.a4o.credentialstorage.helpers.StringHelper;
import com.microsoft.a4o.credentialstorage.helpers.StringHelperTest;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

public class XmlHelperTest {

    @Test
    public void getText_typical() throws Exception {
        final String inputXmlString =
            "<?xml version='1.0' encoding='UTF-8' standalone='no'?>\n" +
            "<value>I am a jelly donut.</value>";
        final byte[] inputXmlBytes = StringHelper.UTF8GetBytes(inputXmlString);
        final ByteArrayInputStream bais = new ByteArrayInputStream(inputXmlBytes);
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = dbf.newDocumentBuilder();
        final Document document = builder.parse(bais);
        final Element rootNode = document.getDocumentElement();

        final String actual = XmlHelper.getText(rootNode);

        Assert.assertEquals("I am a jelly donut.", actual);
    }

    @Test
    public void toString_typical() throws Exception {
        final String inputXmlString =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" +
            "<value>I am a jelly donut.</value>\n";
        final byte[] inputXmlBytes = StringHelper.UTF8GetBytes(inputXmlString);
        final ByteArrayInputStream bais = new ByteArrayInputStream(inputXmlBytes);
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = dbf.newDocumentBuilder();
        final Document document = builder.parse(bais);

        final String actual = XmlHelper.toString(document);

        StringHelperTest.assertLinesEqual(inputXmlString, actual);
    }
}