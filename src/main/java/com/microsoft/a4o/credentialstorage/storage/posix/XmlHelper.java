// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;

/**
 * Helper methods for XML serialization.
 */
public final class XmlHelper {
    private XmlHelper() {
    }

    /**
     * Serialize XML Node to a string.
     * Adapted from http://docs.oracle.com/javase/tutorial/jaxp/dom/readingXML.html
     *
     * @param node XML node
     * @return string representation
     */
    public static String toString(final Node node) {
        final StringBuilder result = new StringBuilder();
        if (!node.hasChildNodes()) {
            return "";
        }

        final NodeList list = node.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            final Node subNode = list.item(i);
            if (subNode.getNodeType() == Node.TEXT_NODE) {
                result.append(subNode.getNodeValue());
            } else if (subNode.getNodeType() == Node.CDATA_SECTION_NODE) {
                result.append(subNode.getNodeValue());
            } else if (subNode.getNodeType() == Node.ENTITY_REFERENCE_NODE) {
                // Recurse into the subtree for text
                // (and ignore comments)
                result.append(toString(subNode));
            }
        }

        return result.toString();
    }

    /**
     * Serialize XML Document to a string.
     *
     * @param document XML document
     * @return string representation
     */
    public static String toString(final Document document) {
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();

            final TransformerFactory tf = TransformerFactory.newInstance();
            final Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
            // http://johnsonsolutions.blogspot.ca/2007/08/xml-transformer-indent-doesnt-work-with.html
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(new DOMSource(document), new StreamResult(baos));

            return baos.toString();
        } catch (final TransformerException e) {
            throw new Error(e);
        }
    }

}
