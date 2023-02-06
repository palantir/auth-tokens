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

    private static final BearerToken ALL_CLAIMS_TOKEN = BearerToken.valueOf("header."
            + "eyJzdWIiOiJ3NVAyV1FNQlEwNnB5WEl3U2xCLy9BPT0iLCJzaWQiOiJQOFpqMUQ1SVRlMjZUdGVLK1l1RFl3PT0iLCJqdGkiOiJwRm0w"
            + "b1ZDSlQrQ0dWZFhmMmJLMy9RPT0iLCJvcmciOiJGQlMycTgvbFQvMnNBRktxZ09pUW13PT0iLCJleHAiOiAxNTc3ODY1NjAwfQ"
            + ".signature");

    private static final BearerToken REQUIRED_CLAIMS_TOKEN = BearerToken.valueOf(
            "header." + "eyJzdWIiOiJ3NVAyV1FNQlEwNnB5WEl3U2xCLy9BPT0iLCJleHAiOiAxNTc3ODY1NjAwfQ" + ".signature");

    private static final BearerToken INVALID_BEARER_TOKEN = BearerToken.valueOf("InvalidBearerToken");

    private static final BearerToken INVALID_ENCODING_TOKEN = BearerToken.valueOf("header."
            + "eyJzdWIiOiJrazlVMHB0ZVJ3K1FYYk55ZkZkcklBPT0iLCJqdGkiOiJ2MEtCNWdVTFJkT3dFWWh4Z1o3bERnPT0ifQo+"
            + ".signature");

    private static final BearerToken INVALID_PAYLOAD_TOKEN = BearerToken.valueOf("header."
            + "eyJzdWIiOiJrazlVMHB0ZVJ3K1FYYk55ZkZkcklBPT0iLCJqdGkiOiJ2MEtCNWdVTFJkT3dFWWh4Z1o3bERnPT0iCg"
            + ".signature");

    private static final String USERID = "c393f659-0301-434e-a9c9-72304a507ffc";
    private static final String SESSION_ID = "3fc663d4-3e48-4ded-ba4e-d78af98b8363";
    private static final String TOKEN_ID = "a459b4a1-5089-4fe0-8655-d5dfd9b2b7fd";
    private static final String ORGANIZATION_ID = "1414b6ab-cfe5-4ffd-ac00-52aa80e8909b";

    @Test
    void testAsJwt_allClaims() {
        UnverifiedJsonWebToken token = UnverifiedJsonWebToken.of(ALL_CLAIMS_TOKEN);
        assertThat(token.getUnverifiedUserId()).isEqualTo(USERID);
        assertThat(token.getUnverifiedSessionId()).contains(SESSION_ID);
        assertThat(token.getUnverifiedTokenId()).contains(TOKEN_ID);
        assertThat(token.getUnverifiedOrganizationId()).contains(ORGANIZATION_ID);

        Optional<UnverifiedJsonWebToken> tryToken = UnverifiedJsonWebToken.tryParse(ALL_CLAIMS_TOKEN.getToken());
        assertThat(tryToken).contains(token);
    }

    @Test
    void testAsJwt_requiredClaims() {
        UnverifiedJsonWebToken token = UnverifiedJsonWebToken.of(REQUIRED_CLAIMS_TOKEN);
        assertThat(token.getUnverifiedUserId()).isEqualTo(USERID);
        assertThat(token.getUnverifiedSessionId()).isEmpty();
        assertThat(token.getUnverifiedTokenId()).isEmpty();
        assertThat(token.getUnverifiedOrganizationId()).isEmpty();

        Optional<UnverifiedJsonWebToken> tryToken = UnverifiedJsonWebToken.tryParse(REQUIRED_CLAIMS_TOKEN.getToken());
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
