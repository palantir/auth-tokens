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

package com.palantir.tokens.auth2;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public final class AuthHeaderTest {

    @Test
    public void testSimple() {
        BearerToken fromToken = BearerToken.valueOf("tokenTest");
        AuthHeader authHeader = AuthHeader.of(fromToken);
        assertThat(authHeader.getBearerToken()).isEqualTo(fromToken);
        assertThat(authHeader.toString()).isEqualTo("Bearer tokenTest");
        assertThat(AuthHeader.valueOf(authHeader.toString())).isEqualTo(authHeader);
    }

    @Test
    public void testToApiToken() {
        assertThat(AuthHeader.valueOf("Bearer apiToken")).isEqualTo(AuthHeader.of(BearerToken.valueOf("apiToken")));
    }

    @Test
    public void testToApiToken_removeFirstBearer() {
        assertThat(AuthHeader.valueOf("Bearer Bearer")).isEqualTo(AuthHeader.of(BearerToken.valueOf("Bearer")));
    }

}
