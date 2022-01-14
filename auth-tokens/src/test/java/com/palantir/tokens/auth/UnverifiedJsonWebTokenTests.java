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

import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.testing.Assertions;
import java.io.IOException;
import java.util.Optional;
import org.junit.jupiter.api.Test;

final class UnverifiedJsonWebTokenTests {

    private static final BearerToken SESSION_TOKEN = BearerToken.valueOf("header."
            + "eyJleHAiOjE0NTk1NTIzNDksInNpZCI6IlA4WmoxRDVJVGUyNlR0ZUsrWXVEWXc9PSIs"
            + "InN1YiI6Inc1UDJXUU1CUTA2cHlYSXdTbEIvL0E9PSJ9"
            + ".signature");

    private static final BearerToken API_TOKEN = BearerToken.valueOf("header."
            + "eyJleHAiOjE0NTk1NTIzNDksInN1YiI6Inc1UDJXUU1CUTA2cHlYSXdTbEIvL0E9PSIs"
            + "Imp0aSI6InBGbTBvVkNKVCtDR1ZkWGYyYkszL1E9PSJ9."
            + "signature");

    private static final BearerToken INVALID_BEARER_TOKEN = BearerToken.valueOf("InvalidBearerToken");

    private static final BearerToken INVALID_ENCODING_TOKEN = BearerToken.valueOf("header."
            + "eyJzdWIiOiJrazlVMHB0ZVJ3K1FYYk55ZkZkcklBPT0iLCJqdGkiOiJ2MEtCNWdVTFJkT3dFWWh4Z1o3bERnPT0ifQo+."
            + "signature");

    private static final BearerToken INVALID_PAYLOAD_TOKEN = BearerToken.valueOf("header."
            + "eyJzdWIiOiJrazlVMHB0ZVJ3K1FYYk55ZkZkcklBPT0iLCJqdGkiOiJ2MEtCNWdVTFJkT3dFWWh4Z1o3bERnPT0iCg."
            + "signature");

    private static final String USERID = "c393f659-0301-434e-a9c9-72304a507ffc";
    private static final String SESSION_ID = "3fc663d4-3e48-4ded-ba4e-d78af98b8363";
    private static final String TOKEN_ID = "a459b4a1-5089-4fe0-8655-d5dfd9b2b7fd";

    @Test
    void testAsJwt_validJwtFromSessionToken() {
        UnverifiedJsonWebToken token = UnverifiedJsonWebToken.of(SESSION_TOKEN);
        assertThat(token.getUnverifiedUserId()).isEqualTo(USERID);
        assertThat(token.getUnverifiedSessionId()).contains(SESSION_ID);
        assertThat(token.getUnverifiedTokenId()).isEmpty();

        Optional<UnverifiedJsonWebToken> tryToken = UnverifiedJsonWebToken.tryParse(SESSION_TOKEN.getToken());
        assertThat(tryToken).contains(token);
    }

    @Test
    void testAsJwt_validJwtFromApiToken() {
        UnverifiedJsonWebToken token = UnverifiedJsonWebToken.of(API_TOKEN);
        assertThat(token.getUnverifiedUserId()).isEqualTo(USERID);
        assertThat(token.getUnverifiedSessionId()).isEmpty();
        assertThat(token.getUnverifiedTokenId()).contains(TOKEN_ID);

        Optional<UnverifiedJsonWebToken> tryToken = UnverifiedJsonWebToken.tryParse(API_TOKEN.getToken());
        assertThat(tryToken).contains(token);
    }

    @Test
    void invalidJwt_parseReturnsEmpty() {
        Optional<UnverifiedJsonWebToken> parsedJwt = UnverifiedJsonWebToken.tryParse(INVALID_BEARER_TOKEN.getToken());
        assertThat(parsedJwt).isNotPresent();
    }

    @Test
    void invalidJwt_parseReturnsEmpty_validStructure() {
        Optional<UnverifiedJsonWebToken> parsedJwt = UnverifiedJsonWebToken.tryParse(INVALID_PAYLOAD_TOKEN.getToken());
        assertThat(parsedJwt).isNotPresent();
    }

    @Test
    void invalidJwt_invalidNumberOfSegments() {
        Assertions.assertThatLoggableExceptionThrownBy(() -> UnverifiedJsonWebToken.of(INVALID_BEARER_TOKEN))
                .hasLogMessage("Invalid JWT: expected 3 segments")
                .hasExactlyArgs(SafeArg.of("segmentsCount", 1))
                .hasNoCause();
    }

    @Test
    void invalidJwt_invalidEncodingToken() {
        Assertions.assertThatLoggableExceptionThrownBy(() -> UnverifiedJsonWebToken.of(INVALID_ENCODING_TOKEN))
                .hasLogMessage("Invalid JWT: cannot parse payload")
                .hasNoArgs()
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void invalidJwt_invalidPayloadToken() {
        Assertions.assertThatLoggableExceptionThrownBy(() -> UnverifiedJsonWebToken.of(INVALID_PAYLOAD_TOKEN))
                .hasLogMessage("Invalid JWT: cannot parse payload")
                .hasNoArgs()
                .hasCauseInstanceOf(IOException.class);
    }
}
