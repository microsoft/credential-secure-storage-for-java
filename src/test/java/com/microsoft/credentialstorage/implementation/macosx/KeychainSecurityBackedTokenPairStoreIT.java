// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.macosx;

import com.microsoft.credentialstorage.model.StoredTokenPair;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class KeychainSecurityBackedTokenPairStoreIT {

    private KeychainSecurityBackedTokenPairStore underTest;

    @Before
    public void setup() {
        assumeTrue(KeychainSecurityCliStore.isSupported());

        underTest = new KeychainSecurityBackedTokenPairStore();
    }

    @Test
    public void e2eTestStoreReadDelete() {
        char[] sampleAccessToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlliUkFRUlljRV9tb3RXVkpLSHJ3TEJiZF85cyIsImtpZCI6IlliUkFRUlljRV9tb3RXVkpLSHJ3TEJiZF85cyJ9.eyKhdWQiOiJodHRwczovL43hbmFnZW1lbnQuY29yZS53aW5kb3dzLc7ldC8iLCJpc3MiOiLidHRwczovL3N0cy53aW5kb3dzLm5ldC9mOGNkZWYzMS1hMzFlLTRiNGEtOTNlNC01ZjU3MWU5MTI1NWEvIiwiaWF0IjoxNDY4ODY1MzM3LCJuYmYiOjE0Njg4NjUzMzcsImV4cCI6MTQ2ODg2OTIzNywiYWNyIjoiMSIsImFsdHNlY2lkIjoiMTpsaXZlLmNvbTowMDAzNDAwMTlBNkM2M0I3IiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6Ijk3ODc3ZjExLTBmYzYtNGFlZS1iMWZmLWZlYmIwNTE5ZGQwMCIsImFwcGlkYWNyIjoiMCIsImVtYWlsIjoieWNhbzIzM0BnbWFpbC5jb20iLCJmYW1pbHlfbmFtZSI6IkNhbyIsImdpdmVuX25hbWUiOiJZYW5nIiwiaWRwIjoibGl2ZS5jb20iLCJpcGFkZHIiOiIxNjcuMjIwLjE0OC4xMDgiLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzdWIiOiJvV0RIMkRWNHptSVQ0dmY2VGxycFZzSFRSYkpUWktpcFItOF9wLVlULWlnIiwidGlkIjoiZjhjZGVmMzEtYTMxZS00YjRhLTkzZTQtNWY1NzFlOTEyNTVhIiwidW5pcXVlX25hbWUiOiJsaXZlLmNvbSN5Y2FvMjMzQGdtYWlsLmNvbSIsInZlciI6IjEuMCJ9.olzZDq52saLRuCxyilW6IgUl1TOudryfaJmwvDadQHAdfqe6KgaN7pE9gm3Wg7CTI0ElzQlVA2BdG2oX-DqBZZjNlvy0Wk9LMOMq6NzR-mf4ksqy1NN_i__cC5WffmQwaE3K-tk6A0llE2e4qjV162EER-ZIfwlAi6uwrJv5vq2UyEGYAU1XqBQ439RxcYG5enYQWB83i0ju-Jl-j-ABjtCmz4UKco96O7xKR9G2eTRLp411Lrn1BTEoNWVMCBzTafDY4wCGSrIWo-KarnJC8o95nKFhxyuBuwYyhMJW_oPVoq6XeL2Z8kCtBc_nJKicS21nazmVHe6Cpijev38CeA".toCharArray();
        char[] sampleRefreshToken = "AABAAAA0TWENU4YUUq5uvDvmnaQie4s-6IJVJQZvwtU53i_arTnRLnbhuIsa2YbtXbPpaP6w8Zr3nNeN3av03Dz2yAyMg9KjFKHEU4nxmM1K2H30sywVia1g78emt20KZEJ5ScaWIowzCWxCRZPpatu5Ktf1q2b1lwtlvvI5gUF5IntfwxMiiR5DFMh51HYeHcISDGi-l1rpoyQ4qWqBPRJ_8GMIlM_YwX2YS0m8iLNlVIhz2BgQa2Ic10SzBlvIZkNXlLN1EBxOzHE5Q93HGaJtOXrAyFzXPUv3FyvsYzbhfF5PHX9YnBrinWO9bhCSIZNAx9PHw_XL9LWhad6MXO1zykYSVlss2VUrz9Cuz4SVonS1bokLWBVlITr1hYbL68qJOWYsgoNc_yWMyTMdeCDcFsZGC0EVClrMsE7KW39CebZzF9g7QH6prsHGT1sqKUh1F54oCQSb7zV4A2WsRfxvoE8jS3_r0BWwZb5frUKt0ZO1A080sGag7mwtTcanVB2U2oqkpVOJhfV3NqCEshvk94AhG3Dm-gl4nrdhcvAlOVgg9UFvbLoVSb44m1CcxxBdTybW1Kzd44wdR63r_dA1CW_11ZzDOV792MPgyUtJqaKXYcgAA".toCharArray();

        StoredTokenPair tokenPair = new StoredTokenPair(sampleAccessToken, sampleRefreshToken);
        String key = "KeychainTest:http://test.com:Token";

        boolean added = underTest.add(key, tokenPair);
        assertTrue("Storing token pair failed", added);

        StoredTokenPair readTokenPair = underTest.get(key);

        assertNotNull("Token pair not found", readTokenPair);
        assertArrayEquals("Retrieved Access Token is different", sampleAccessToken, readTokenPair.getAccessToken().getValue());
        assertArrayEquals("Retrieved Refresh Token is different", sampleRefreshToken, readTokenPair.getRefreshToken().getValue());

        boolean deleted = underTest.delete(key);
        assertTrue("Token pair not deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Token pair deleted twice, did first delete fail?", deleted);

        StoredTokenPair nonExistent = underTest.get(key);
        assertNull("Token can still be read from store", nonExistent);
    }
}