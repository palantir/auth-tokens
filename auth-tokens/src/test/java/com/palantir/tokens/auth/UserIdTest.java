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

import static org.junit.Assert.assertEquals;

import com.google.common.base.Optional;
import org.junit.Test;

public final class UserIdTest {
    private static final BearerToken SESSION_TOKEN = BearerToken.valueOf("eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE0NTk1NTIzNDks"
            + "InNpZCI6IlA4WmoxRDVJVGUyNlR0ZUsrWXVEWXc9PSIsInN1YiI6Inc1UDJXUU1CUTA2cHlYSXdTbEIvL0E9PSJ9.XwPO_EEDVj6BBLS"
            + "cuf70_CH4jyI1ECmgVSoXLHpGlK-yIqm8MyUyFyNQTu8jh9kYheW-zBl64gmTnatkjjDH1A");

    private static final BearerToken API_TOKEN = BearerToken.valueOf("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ3NVAyV1FNQ"
            + "lEwNnB5WEl3U2xCLy9BPT0iLCJqdGkiOiJwRm0wb1ZDSlQrQ0dWZFhmMmJLMy9RPT0ifQ.hBUerwGsc4FFPIujHJ-7ncGe3-zZQcdPOu"
            + "RZ8B84nzPNYjlyPmB8VLizsvR23CK3KQUEAlQ2AN_9a5p5_WgPAQ");

    private static final BearerToken INVALID_BEARER_TOKEN = BearerToken.valueOf("IncorrectBearerToken");

    private static final String USERID = "c393f659-0301-434e-a9c9-72304a507ffc";

    @Test
    public void canExtractUserIdFromSessionToken() {
        assertEquals(Optional.of(USERID), SESSION_TOKEN.getUserIdInsecure());
    }

    @Test
    public void canExtractUserIdFromApiToken() {
        assertEquals(Optional.of(USERID), API_TOKEN.getUserIdInsecure());
    }

    @Test
    public void incorrectBearerTokenGetsFailureMessage() {
        assertEquals(Optional.absent(), INVALID_BEARER_TOKEN.getUserIdInsecure());
    }
}
