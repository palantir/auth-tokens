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
import io.dropwizard.Application;
import io.dropwizard.Configuration;
import io.dropwizard.setup.Environment;
import io.dropwizard.testing.junit.DropwizardAppRule;
import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.slf4j.MDC;

public class BearerTokenLoggingFeatureIntegTest {

    @ClassRule
    public static final DropwizardAppRule<Configuration> app = new DropwizardAppRule<>(Server.class);

    private WebTarget target;

    @Before
    public void before() {
        String endpointUri = "http://localhost:" + app.getLocalPort();
        JerseyClientBuilder builder = new JerseyClientBuilder();
        Client client = builder.build();
        target = client.target(endpointUri);
    }

    @Test
    public void mdc_values_should_be_populated_from_http_header() {
        assertThat(target.path("/success").request()
                .header("Authorization", TestConstants.AUTH_HEADER)
                .get()
                .getStatus()).isEqualTo(200);
    }

    @Test
    public void mdc_values_should_be_populated_when_cookie_is_a_bearertoken() {
        assertThat(target.path("/cookies").request()
                .cookie(new Cookie(
                        "SOME_COOKIE",
                        AuthHeader.valueOf(TestConstants.AUTH_HEADER).getBearerToken().toString()))
                .get()
                .getStatus()).isEqualTo(200);
    }

    @Test
    public void auth_header_passed_to_no_header_endpoint_is_not_picked_up() {
        assertThat(target.path("/no-header").request()
                .header("Authorization", TestConstants.AUTH_HEADER)
                .get()
                .getStatus()).isEqualTo(200);
    }

    @Test
    public void non_auth_cookie_doesnt_get_logged() {
        assertThat(target.path("/non-auth-cookie").request()
                .cookie(new Cookie(
                        "SOME_COOKIE",
                        AuthHeader.valueOf(TestConstants.AUTH_HEADER).getBearerToken().toString()))
                .get()
                .getStatus()).isEqualTo(200);
    }

    public static final class Server extends Application<Configuration> {
        @Override
        public void run(Configuration configuration, Environment environment) throws Exception {
            environment.jersey().register(new Resource());
            environment.jersey().register(BearerTokenLoggingFeature.class);
        }
    }

    @Path("/")
    public static final class Resource {

        @GET
        @Path("success")
        public boolean success(@HeaderParam(HttpHeaders.AUTHORIZATION) AuthHeader unused) {
            assertThat(MDC.get("userId")).isEqualTo(TestConstants.USER_ID);
            assertThat(MDC.get("sessionId")).isEqualTo(TestConstants.SESSION_ID);
            assertThat(MDC.get("tokenId")).isEqualTo(TestConstants.TOKEN_ID);
            return true;
        }

        @GET
        @Path("cookies")
        public boolean cookies(@CookieParam("SOME_COOKIE") BearerToken unused) {
            assertThat(MDC.get("userId")).isEqualTo(TestConstants.USER_ID);
            assertThat(MDC.get("sessionId")).isEqualTo(TestConstants.SESSION_ID);
            assertThat(MDC.get("tokenId")).isEqualTo(TestConstants.TOKEN_ID);
            return true;
        }

        @GET
        @Path("non-auth-cookie")
        public boolean nonAuthCookie(@CookieParam("NON_AUTH_COOKIE") Integer unused) {
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
