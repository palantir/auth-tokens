/*
 * (c) Copyright 2016 Palantir Technologies Inc. All rights reserved.
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.testing.Assertions;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link BearerToken}.
 */
final class BearerTokenTests {

    private static final String TOKEN_STRING = "abc123";

    @Test
    void testConstructorUsage() {
        BearerToken bearerToken = BearerToken.valueOf(TOKEN_STRING);
        assertThat(bearerToken.getToken()).isEqualTo(TOKEN_STRING);
    }

    @Test
    void testFromString_specialCharacters() {
        List<String> validTokens = Arrays.asList("-._~+/=", "a", "abc", "abc=", "a=", "a===");
        for (String validToken : validTokens) {
            BearerToken.valueOf(validToken);
        }
    }

    @Test
    void testFromString_invalidTokens() {
        List<String> invalidTokens = Arrays.asList(" space", "space ", "with space", "#", " ", "(", "=", "=a");
        for (String invalidToken : invalidTokens) {
            Assertions.assertThatLoggableExceptionThrownBy(() -> BearerToken.valueOf(invalidToken))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasLogMessage("BearerToken must match pattern")
                    .hasExactlyArgs(SafeArg.of("validationPattern", "^[A-Za-z0-9\\-\\._~\\+/]+=*$"));
        }
    }

    @Test
    void testTokenCannotBeBlank() {
        assertThatThrownBy(() -> BearerToken.valueOf("")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testTokenCannotBeNull() {
        assertThatThrownBy(() -> BearerToken.valueOf(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testJackson() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        BearerToken expectedBearerToken = BearerToken.valueOf(TOKEN_STRING);
        String json = objectMapper.writeValueAsString(expectedBearerToken);
        BearerToken actualBearerToken = objectMapper.readValue(json, BearerToken.class);

        assertThat(json).isEqualTo("\"abc123\"");
        assertThat(actualBearerToken).isEqualTo(expectedBearerToken);
    }

    @Test
    void testJacksonInContainer() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        TokenContainer expectedContainer = new TokenContainer(BearerToken.valueOf(TOKEN_STRING));
        String json = objectMapper.writeValueAsString(expectedContainer);
        TokenContainer actualContainer = objectMapper.readValue(json, TokenContainer.class);

        assertThat(actualContainer.getToken()).isEqualTo(expectedContainer.getToken());
    }

    @Test
    void testToString() {
        BearerToken bearerToken = BearerToken.valueOf(TOKEN_STRING);
        assertThat(bearerToken.toString()).isEqualTo(TOKEN_STRING);
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
