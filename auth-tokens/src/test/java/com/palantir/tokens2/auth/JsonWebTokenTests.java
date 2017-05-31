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

package com.palantir.tokens2.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Optional;
import org.junit.Test;

public final class JsonWebTokenTests {

    private static final BearerToken SESSION_TOKEN = BearerToken.valueOf("eyJhbGciOiJFUzI1NiJ9."
            + "eyJleHAiOjE0NTk1NTIzNDksInNpZCI6IlA4WmoxRDVJVGUyNlR0Z"
            + "UsrWXVEWXc9PSIsInN1YiI6Inc1UDJXUU1CUTA2cHlYSXdTbEIvL0E9PSJ9"
            + ".XwPO_EEDVj6BBLScuf70_CH4jyI1ECmgVSoXLHpGlK-yIqm8MyUyFyNQTu8jh9kYheW-zBl64gmTnatkjjDH1A");

    private static final BearerToken API_TOKEN = BearerToken.valueOf("eyJhbGciOiJFUzI1NiJ9."
            + "eyJzdWIiOiJ3NVAyV1FNQlEwNnB5WEl3U2xCLy9BPT0iLCJqdGkiOiJwRm0wb1ZDSlQrQ0dWZFhmMmJLMy9RPT0ifQ."
            + "hBUerwGsc4FFPIujHJ-7ncGe3-zZQcdPOuRZ8B84nzPNYjlyPmB8VLizsvR23CK3KQUEAlQ2AN_9a5p5_WgPAQ");

    private static final BearerToken INVALID_BEARER_TOKEN = BearerToken.valueOf("IncorrectBearerToken");

    private static final BearerToken INVALID_PAYLOAD_TOKEN = BearerToken.valueOf("eyJhbGciOiJFUzI1NiJ9."
            + "eyJzdWIiOiJrazlVMHB0ZVJ3K1FYYk55ZkZkcklBPT0iLCJqdGkiOiJ2MEtCNWdVTFJkT3dFWWh4Z1o3bERnPT0iCg."
            + "hBUerwGsc4FFPIujHJ-7ncGe3-zZQcdPOuRZ8B84nzPNYjlyPmB8VLizsvR23CK3KQUEAlQ2AN_9a5p5_WgPAQ");

    private static final String USERID = "c393f659-0301-434e-a9c9-72304a507ffc";
    private static final String SESSION_ID = "3fc663d4-3e48-4ded-ba4e-d78af98b8363";

    @Test
    public void testAsJwt_validJwtFromSessionToken() {
        UnverifiedJsonWebToken token = UnverifiedJsonWebToken.of(SESSION_TOKEN);
        assertEquals(USERID, token.getUnverifiedUserId());
        assertEquals(Optional.of(SESSION_ID), token.getUnverifiedSessionId());
    }

    @Test
    public void testAsJwt_validJwtFromApiToken() {
        UnverifiedJsonWebToken token = UnverifiedJsonWebToken.of(API_TOKEN);
        assertEquals(USERID, token.getUnverifiedUserId());
        assertEquals(Optional.empty(), token.getUnverifiedSessionId());
    }

    @Test
    public void invalidJwt_invalidNumberOfSegments() {
        try {
            UnverifiedJsonWebToken.of(INVALID_BEARER_TOKEN);
            fail();
        } catch (RuntimeException e) {
            assertEquals("Invalid JWT: expected 3 segments, found 1", e.getMessage());
        }
    }

    @Test
    public void invalidJwt_invalidPayloadToken() {
        try {
            UnverifiedJsonWebToken.of(INVALID_PAYLOAD_TOKEN);
            fail();
        } catch (RuntimeException e) {
            assertEquals("Invalid JWT: cannot parse payload", e.getMessage());
        }
    }

}
