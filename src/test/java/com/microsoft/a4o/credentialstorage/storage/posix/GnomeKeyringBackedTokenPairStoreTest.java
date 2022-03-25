// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix;

import com.microsoft.a4o.credentialstorage.helpers.StringHelperTest;
import com.microsoft.a4o.credentialstorage.secret.TokenPair;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

import static org.junit.Assert.assertEquals;


public class GnomeKeyringBackedTokenPairStoreTest {

    GnomeKeyringBackedTokenPairStore underTest;

    private static final String SAMPLE_ASSESS_TOKEN =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWW" +
            "lKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiJodHRwcz" +
            "ovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9" +
            "mOGNkZWYzMS1hMzFlLTRiNGEtOTNlNC01ZjU3MWU5MTI1NWEvIiwiaWF0IjoxNDU4NzUwOTc3LCJuYmYiOjE0NT" +
            "g3NTA5NzcsImV4cCI6MTQ1ODc1NDg3NywiYWNyIjoiMSIsImFsdHNlY2lkIjoiMTpsaXZlLmNvbTowMDAzNDAwMT" +
            "ItOF9wLVlULWlnIiwidGlkIjoiZjhjZGVmMzEtYTMxZS00YjRhLTkzZTQtNWY1NzFlOTEyNTVhIiwidW5pcXVlX2" +
            "k2OSIsImFwcGlkYWNyIjoiMCIsImVtYWlsIjoieWNhbzIzM0BnbWFpbC5jb20iLCJmYW1pbHlfbmFtZSI6IkNhby" +
            "IsImdpdmVuX25hbWUiOiJZYW5nIiwiaWRwIjoibGl2ZS5jb20iLCJpcGFkZHIiOiIxNjcuMjIwLjE0OC4xMTAiLC" +
            "JzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzdWIiOiJvV0RIMkRWNHptSVQ0dmY2VGxycFZzSFRSYkpUWktpcF" +
            "IG9FrPoEMZt_sVlJQjOZYq4NTjVXdj5Gpnl4IKHxmAcz4DREG1z5mBUtPnh-ku6UJm-Maed9iufyEYhXAyovwXDwa" +
            "5hbWUiOiJsaXZlLmNvbSN5Y2FvMjMzQGdtYWlsLmNvbSIsInZlciI6IjEuMCJ9.kq1MN9V-TANaDu0HaLey0QZUV" +
            "NKm0HNUEHElZhicVxbZFrYimvJUL1OIzvpMIgQni8UatHiOxq6sgLQymmk2G6Y2DBzWL_wd2RqdXuyOi_TZi3jVl" +
            "lcDkM2M0I3IiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6IjUwMmVhMjFkLWU1NDUtNGM2Ni05MTI5LWMzNTJlYzkwMj" +
            "NQFecidci7Xr_aGSFTq1KMK2dwDz1LDdVbSx8wJP__LU3DDPzUR-eitSdXkMFLBzZpMA92nPhBAQWnks0xEtEd3" +
            "pK_Jerl82xaK5IhVzEhkh70deCDgGB_90DoxlGf93Aursq5I5WKRQ";

    private static final String SAMPLE_REFRESH_TOKEN =
            "AAABAAAAiL9Kn2Z27UubvWFPbm0gLWTuMRxgA2q_tw71qiUQeaQ2JiRdQOroj2" +
            "7iBaKg7AFEMyE-V_DdbHvY6SIkJJHstS_xfWN_2zquKaHTrHI_EgIX7ZS7Ik8ChNTcba8g8d4geT72x9mosR9HZkwY" +
            "eUN1y9wr9f5ECmiCCisDNUNk9bvx86ZnpsJ3DtsQyaPmqcSf5cxQ3XX7fjGljZ0JyWCeCdnNcKsvrBajfWIpW37K3wXpoC" +
            "NFNIthL--rcchCXHd1yOaBtSWZmhL2bObot00mOeQh42mp01JgNH2EtqStPUA3a63hIrUMLWSVNyxCA5xgMsryygro" +
            "MhQAJEP0ufZL7mK7DZU6_TS9K8GX61Y3f2IWjtKuDvFnoBsS1taYf6DY0jZZ3prRC2PM4p5xKpyGiYn5ibsgTpkDl" +
            "e9po5P_sE5flQEBNZ7orOghChj63DxV2usxJDekTb5r9x8L1qH2sSrhavPzbqvn6hb2lF6FXHq6Z6SxDY4UDsQhhzDhl" +
            "n71n1yP0mLmz24-5MP0DCFVU3Du4mjcf5AFjqw3Sv3WXGFMUp1x2_wswzXYSZQCQNRUIAA";

    @Before
    public void setUp() throws Exception {
        underTest = new GnomeKeyringBackedTokenPairStore();
    }

    @Test
    public void serializeDeserialize_tokens() {
        final TokenPair tokenPair = new TokenPair(SAMPLE_ASSESS_TOKEN, SAMPLE_REFRESH_TOKEN);

        final String serialized = underTest.serialize(tokenPair);
        final TokenPair processed = underTest.deserialize(serialized);

        assertEquals(tokenPair.getAccessToken(), processed.getAccessToken());
        assertEquals(tokenPair.getRefreshToken(), processed.getRefreshToken());
    }

    @Test
    public void xmlSerialization_roundTrip() throws Exception {
        final TokenPair tokenPair =
                new TokenPair("9297fb18-46d0-4846-97ca-ab8dd3b55729", "d15281b1-03f1-4581-90d3-4527d9cf4147");
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = dbf.newDocumentBuilder();
        final Document serializationDoc = builder.newDocument();

        final Element element = GnomeKeyringBackedTokenPairStore.toXml(tokenPair, serializationDoc);

        serializationDoc.appendChild(element);
        final String actualXmlString = XmlHelper.toString(serializationDoc);
        final String expectedXmlString =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" +
                        "<value>\n" +
                        "    <accessToken>9297fb18-46d0-4846-97ca-ab8dd3b55729</accessToken>\n" +
                        "    <refreshToken>d15281b1-03f1-4581-90d3-4527d9cf4147</refreshToken>\n" +
                        "</value>";
        StringHelperTest.assertLinesEqual(expectedXmlString, actualXmlString);

        final ByteArrayInputStream bais = new ByteArrayInputStream(actualXmlString.getBytes());
        final Document deserializationDoc = builder.parse(bais);
        final Element rootNode = deserializationDoc.getDocumentElement();

        final TokenPair actualTokenPair = GnomeKeyringBackedTokenPairStore.fromXml(rootNode);

        assertEquals(tokenPair.getAccessToken().getValue(), actualTokenPair.getAccessToken().getValue());
        assertEquals(tokenPair.getRefreshToken().getValue(), actualTokenPair.getRefreshToken().getValue());
    }
}