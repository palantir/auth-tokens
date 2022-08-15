/*
 * (c) Copyright 2019 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.tokens.auth.http;

import static org.assertj.core.api.Assertions.assertThat;

import com.palantir.tokens.auth.AuthHeader;
import com.palantir.tokens.auth.BearerToken;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.HttpHeaders;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;

final class BearerTokenLoggingFeatureIntegTest {

    @RegisterExtension
    private static final UndertowServerExtension undertow = UndertowServerExtension.create()
            .jersey(new ResourceImpl())
            .jersey(new DirectResource())
            .jersey(new BearerTokenLoggingFeature());

    @ParameterizedTest
    @ValueSource(strings = {"/direct", "/inherited"})
    void mdc_values_should_be_populated_from_http_header(String pathPrefix) {
        undertow.runRequest(
                ClassicRequestBuilder.get(pathPrefix + "/success")
                        .addHeader("Authorization", TestConstants.AUTH_HEADER)
                        .build(),
                response -> {
                    assertThat(response.getCode()).isEqualTo(200);
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"/direct", "/inherited"})
    void mdc_values_should_be_populated_when_cookie_is_a_bearertoken(String pathPrefix) {
        undertow.runRequest(
                ClassicRequestBuilder.get(pathPrefix + "/cookies")
                        .addHeader(
                                "Cookie",
                                "SOME_COOKIE="
                                        + AuthHeader.valueOf(TestConstants.AUTH_HEADER)
                                                .getBearerToken()
                                                .toString())
                        .build(),
                response -> {
                    assertThat(response.getCode()).isEqualTo(200);
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"/direct", "/inherited"})
    void auth_header_passed_to_no_header_endpoint_is_not_picked_up(String pathPrefix) {
        undertow.runRequest(
                ClassicRequestBuilder.get(pathPrefix + "/no-header")
                        .addHeader("Authorization", TestConstants.AUTH_HEADER)
                        .build(),
                response -> {
                    assertThat(response.getCode()).isEqualTo(200);
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"/direct", "/inherited"})
    void non_auth_cookie_doesnt_get_logged(String pathPrefix) {
        undertow.runRequest(
                ClassicRequestBuilder.get(pathPrefix + "/non-auth-cookie")
                        .addHeader(
                                "Cookie",
                                "SOME_COOKIE="
                                        + AuthHeader.valueOf(TestConstants.AUTH_HEADER)
                                                .getBearerToken()
                                                .toString())
                        .build(),
                response -> {
                    assertThat(response.getCode()).isEqualTo(200);
                });
    }

    @Path("/inherited")
    public interface Resource {
        @GET
        @Path("success")
        boolean success(@HeaderParam(HttpHeaders.AUTHORIZATION) AuthHeader unused);

        @GET
        @Path("cookies")
        boolean cookies(@CookieParam("SOME_COOKIE") BearerToken unused);

        @GET
        @Path("non-auth-cookie")
        boolean nonAuthCookie(@CookieParam("NON_AUTH_COOKIE") Integer unused);

        @GET
        @Path("no-header")
        boolean noHeader();
    }

    public static final class ResourceImpl implements Resource {
        @Override
        public boolean success(AuthHeader _value) {
            assertThat(MDC.get("userId")).isEqualTo(TestConstants.USER_ID);
            assertThat(MDC.get("sessionId")).isEqualTo(TestConstants.SESSION_ID);
            assertThat(MDC.get("tokenId")).isEqualTo(TestConstants.TOKEN_ID);
            return true;
        }

        @Override
        public boolean cookies(BearerToken _value) {
            assertThat(MDC.get("userId")).isEqualTo(TestConstants.USER_ID);
            assertThat(MDC.get("sessionId")).isEqualTo(TestConstants.SESSION_ID);
            assertThat(MDC.get("tokenId")).isEqualTo(TestConstants.TOKEN_ID);
            return true;
        }

        @Override
        public boolean nonAuthCookie(Integer _value) {
            assertThat(MDC.get("userId")).isNull();
            assertThat(MDC.get("sessionId")).isNull();
            assertThat(MDC.get("tokenId")).isNull();
            return true;
        }

        @Override
        public boolean noHeader() {
            assertThat(MDC.get("userId")).isNull();
            assertThat(MDC.get("sessionId")).isNull();
            assertThat(MDC.get("tokenId")).isNull();
            return true;
        }
    }

    @Path("/direct")
    public static final class DirectResource {

        @GET
        @Path("success")
        public boolean success(@HeaderParam(HttpHeaders.AUTHORIZATION) AuthHeader _value) {
            assertThat(MDC.get("userId")).isEqualTo(TestConstants.USER_ID);
            assertThat(MDC.get("sessionId")).isEqualTo(TestConstants.SESSION_ID);
            assertThat(MDC.get("tokenId")).isEqualTo(TestConstants.TOKEN_ID);
            return true;
        }

        @GET
        @Path("cookies")
        public boolean cookies(@CookieParam("SOME_COOKIE") BearerToken _value) {
            assertThat(MDC.get("userId")).isEqualTo(TestConstants.USER_ID);
            assertThat(MDC.get("sessionId")).isEqualTo(TestConstants.SESSION_ID);
            assertThat(MDC.get("tokenId")).isEqualTo(TestConstants.TOKEN_ID);
            return true;
        }

        @GET
        @Path("non-auth-cookie")
        public boolean nonAuthCookie(@CookieParam("NON_AUTH_COOKIE") Integer _value) {
            assertThat(MDC.get("userId")).isNull();
            assertThat(MDC.get("sessionId")).isNull();
            assertThat(MDC.get("tokenId")).isNull();
            return true;
        }

        @GET
        @Path("no-header")
        public boolean noHeader() {
            assertThat(MDC.get("userId")).isNull();
            assertThat(MDC.get("sessionId")).isNull();
            assertThat(MDC.get("tokenId")).isNull();
            return true;
        }
    }
}
