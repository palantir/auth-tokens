/*
 * Copyright 2016 Palantir Technologies, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.palantir.tokens.auth;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.util.List;
import org.junit.Test;

/**
 * Tests for {@link BearerToken}.
 */
public final class BearerTokenTests {

    private static final String TOKEN_STRING = "abc123";

    @Test
    public void testConstructorUsage() {
        BearerToken bearerToken = BearerToken.valueOf(TOKEN_STRING);
        assertEquals(TOKEN_STRING, bearerToken.getToken());
    }

    @Test
    public void testFromStringUsage() {
        BearerToken bearerToken = BearerToken.valueOf(TOKEN_STRING);
        assertEquals(TOKEN_STRING, bearerToken.getToken());
    }

    @Test
    public void testFromString_specialCharacters() {
        List<String> validTokens = ImmutableList.of("-._~+/=", "abc=", "a=");
        for (String validToken : validTokens) {
            BearerToken.valueOf(validToken);
        }
    }

    @Test
    public void testFromString_invalidTokens() {
        List<String> invalidTokens = ImmutableList.of(" space", "space ", "with space", "#", " ", "(", "=", "=a");
        for (String invalidToken : invalidTokens) {
            try {
                BearerToken.valueOf(invalidToken);
                fail();
            } catch (IllegalArgumentException e) {
                assertThat(e.getMessage(), is("BearerToken must match pattern "
                        + "^[A-Za-z0-9\\-\\._~\\+/]+=*$: " + invalidToken));
            }
        }
    }

    @Test
    public void testTokenCannotBeBlank() {
        try {
            BearerToken.valueOf("");
            fail();
        } catch (IllegalArgumentException e) {
            // expected
        }
    }

    @Test
    @SuppressFBWarnings("NP_NULL_PARAM_DEREF_NONVIRTUAL")
    public void testTokenCannotBeNull() {
        try {
            BearerToken.valueOf(null);
            fail();
        } catch (IllegalArgumentException e) {
            // expected
        }
    }

    @Test
    public void testJackson() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        BearerToken expectedBearerToken = BearerToken.valueOf(TOKEN_STRING);
        String json = objectMapper.writeValueAsString(expectedBearerToken);
        BearerToken actualBearerToken = objectMapper.readValue(json, BearerToken.class);

        assertEquals("\"abc123\"", json);
        assertEquals(expectedBearerToken, actualBearerToken);
    }

    @Test
    public void testJacksonInContainer() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        TokenContainer expectedContainer = new TokenContainer(BearerToken.valueOf(TOKEN_STRING));
        String json = objectMapper.writeValueAsString(expectedContainer);
        TokenContainer actualContainer = objectMapper.readValue(json, TokenContainer.class);

        assertEquals(expectedContainer.getToken(), actualContainer.getToken());
    }

    @Test
    public void testToString() {
        BearerToken bearerToken = BearerToken.valueOf(TOKEN_STRING);

        assertEquals(TOKEN_STRING, bearerToken.toString());
    }

    private static class TokenContainer {
        private final BearerToken token;

        @JsonCreator
        TokenContainer(@JsonProperty("token") BearerToken token) {
            this.token = token;
        }

        public BearerToken getToken() {
            return this.token;
        }
    }
}
