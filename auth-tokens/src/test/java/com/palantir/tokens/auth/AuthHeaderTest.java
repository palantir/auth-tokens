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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class AuthHeaderTest {

    @Test
    void testFromToken() {
        BearerToken bearerToken = BearerToken.valueOf("bearerToken");

        AuthHeader authHeader = AuthHeader.of(bearerToken);

        assertThat(authHeader.getBearerToken()).isEqualTo(bearerToken);
        assertThat(authHeader.toString()).isEqualTo("Bearer bearerToken");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Bearer bearerToken", "bearer bearerToken", "BeArEr bearerToken", "bearerToken"})
    void testFromString(String authHeaderString) {
        BearerToken bearerToken = BearerToken.valueOf("bearerToken");

        AuthHeader authHeader = AuthHeader.valueOf(authHeaderString);

        assertThat(authHeader.getBearerToken()).isEqualTo(bearerToken);
        assertThat(authHeader.toString()).isEqualTo("Bearer bearerToken");
    }
}
