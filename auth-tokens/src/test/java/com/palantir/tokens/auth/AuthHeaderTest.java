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
import static org.junit.Assert.assertThat;

import org.junit.Test;

public final class AuthHeaderTest {

    @Test
    public void testSimple() {
        BearerToken fromToken = BearerToken.valueOf("tokenTest");
        AuthHeader authHeader = AuthHeader.of(fromToken);
        assertThat(authHeader.getBearerToken(), is(fromToken));
        assertThat(authHeader.toString(), is("Bearer tokenTest"));
        assertThat(AuthHeader.valueOf(authHeader.toString()), is(authHeader));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMissingToken() {
        AuthHeader.valueOf("Bearer");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMissingBearer() {
        AuthHeader.valueOf("someToken");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMultipleTokens() {
        AuthHeader.valueOf("Bearer tokenOne tokenTwo");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNotUsingBearer() {
        AuthHeader.valueOf("Basic username:password");
    }

    @Test
    public void testToApiToken_caseInsensitiveBearer() {
        assertThat(AuthHeader.valueOf("bEaReR apiToken"), is(AuthHeader.of(BearerToken.valueOf("apiToken"))));
    }

    @Test
    public void testToApiToken() {
        assertThat(AuthHeader.valueOf("Bearer apiToken"), is(AuthHeader.of(BearerToken.valueOf("apiToken"))));
    }

    @Test
    public void testToApiToken_removeFirstBearer() {
        assertThat(AuthHeader.valueOf("Bearer Bearer"), is(AuthHeader.of(BearerToken.valueOf("Bearer"))));
    }
}
