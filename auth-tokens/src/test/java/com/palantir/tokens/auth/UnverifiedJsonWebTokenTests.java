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

import static com.palantir.logsafe.testing.Assertions.assertThatLoggableExceptionThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

import com.palantir.logsafe.SafeArg;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

final class UnverifiedJsonWebTokenTests {

    @Test
    void allClaims() {
        BearerToken bearerToken = jwt("""
            {\
            "sub":"w5P2WQMBQ06pyXIwSlB//A==",\
            "sid":"P8Zj1D5ITe26TteK+YuDYw==",\
            "jti":"pFm0oVCJT+CGVdXf2bK3/Q==",\
            "org":"FBS2q8/lT/2sAFKqgOiQmw==",\
            "svc":"service"\
            }\
            """);

        UnverifiedJsonWebToken token = UnverifiedJsonWebToken.of(bearerToken);
        assertThat(token.getUnverifiedUserId()).isEqualTo("c393f659-0301-434e-a9c9-72304a507ffc");
        assertThat(token.getUnverifiedSessionId()).contains("3fc663d4-3e48-4ded-ba4e-d78af98b8363");
        assertThat(token.getUnverifiedTokenId()).contains("a459b4a1-5089-4fe0-8655-d5dfd9b2b7fd");
        assertThat(token.getUnverifiedOrganizationId()).contains("1414b6ab-cfe5-4ffd-ac00-52aa80e8909b");
        assertThat(token.getUnverifiedService()).contains("service");

        assertThat(UnverifiedJsonWebToken.tryParse(bearerToken.getToken())).contains(token);
    }

    @Test
    void requiredClaims() {
        BearerToken bearerToken = jwt("""
            {\
            "sub":"w5P2WQMBQ06pyXIwSlB//A=="\
            }\
            """);

        UnverifiedJsonWebToken token = UnverifiedJsonWebToken.of(bearerToken);
        assertThat(token.getUnverifiedUserId()).isEqualTo("c393f659-0301-434e-a9c9-72304a507ffc");
        assertThat(token.getUnverifiedSessionId()).isEmpty();
        assertThat(token.getUnverifiedTokenId()).isEmpty();
        assertThat(token.getUnverifiedOrganizationId()).isEmpty();
        assertThat(token.getUnverifiedService()).isEmpty();

        assertThat(UnverifiedJsonWebToken.tryParse(bearerToken.getToken())).contains(token);
    }

    @Test
    void tryParse_invalidJwt() {
        BearerToken bearerToken = BearerToken.valueOf("invalid");

        assertThatLoggableExceptionThrownBy(() -> UnverifiedJsonWebToken.of(bearerToken))
                .hasLogMessage("Invalid JWT: expected 3 segments")
                .hasExactlyArgs(SafeArg.of("segmentsCount", 1))
                .hasNoCause();

        assertThat(UnverifiedJsonWebToken.tryParse(bearerToken.getToken())).isEmpty();
    }

    @Test
    void tryParse_invalidEncoding() {
        BearerToken bearerToken = BearerToken.valueOf("header.invalid+.signature");

        assertThatLoggableExceptionThrownBy(() -> UnverifiedJsonWebToken.of(bearerToken))
                .hasLogMessage("Invalid JWT: cannot parse payload")
                .hasNoArgs()
                .hasCauseInstanceOf(IllegalArgumentException.class);

        assertThat(UnverifiedJsonWebToken.tryParse(bearerToken.getToken())).isEmpty();
    }

    @Test
    void tryParse_invalidPayload() {
        BearerToken bearerToken = jwt("""
            invalid\
            """);

        assertThatLoggableExceptionThrownBy(() -> UnverifiedJsonWebToken.of(bearerToken))
                .hasLogMessage("Invalid JWT: cannot parse payload")
                .hasNoArgs()
                .hasCauseInstanceOf(IOException.class);

        assertThat(UnverifiedJsonWebToken.tryParse(bearerToken.getToken())).isEmpty();
    }

    private static BearerToken jwt(String payload) {
        String jwt = "header."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + ".signature";
        return BearerToken.valueOf(jwt);
    }
}
