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
import java.util.Arrays;
import java.util.Collection;
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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.slf4j.MDC;

@RunWith(Parameterized.class)
public class BearerTokenLoggingFeatureIntegTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {{"/direct"}, {"/inherited"}});
    }

    private final String pathPrefix;

    public BearerTokenLoggingFeatureIntegTest(String pathPrefix) {
        this.pathPrefix = pathPrefix;
    }

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
        assertThat(target.path(pathPrefix + "/success")
                        .request()
                        .header("Authorization", TestConstants.AUTH_HEADER)
                        .get()
                        .getStatus())
                .isEqualTo(200);
    }

    @Test
    public void mdc_values_should_be_populated_when_cookie_is_a_bearertoken() {
        assertThat(target.path(pathPrefix + "/cookies")
                        .request()
                        .cookie(new Cookie(
                                "SOME_COOKIE",
                                AuthHeader.valueOf(TestConstants.AUTH_HEADER)
                                        .getBearerToken()
                                        .toString()))
                        .get()
                        .getStatus())
                .isEqualTo(200);
    }

    @Test
    public void auth_header_passed_to_no_header_endpoint_is_not_picked_up() {
        assertThat(target.path(pathPrefix + "/no-header")
                        .request()
                        .header("Authorization", TestConstants.AUTH_HEADER)
                        .get()
                        .getStatus())
                .isEqualTo(200);
    }

    @Test
    public void non_auth_cookie_doesnt_get_logged() {
        assertThat(target.path(pathPrefix + "/non-auth-cookie")
                        .request()
                        .cookie(new Cookie(
                                "SOME_COOKIE",
                                AuthHeader.valueOf(TestConstants.AUTH_HEADER)
                                        .getBearerToken()
                                        .toString()))
                        .get()
                        .getStatus())
                .isEqualTo(200);
    }

    public static final class Server extends Application<Configuration> {
        @Override
        public void run(Configuration _configuration, Environment environment) {
            environment.jersey().register(new ResourceImpl());
            environment.jersey().register(new DirectResource());
            environment.jersey().register(BearerTokenLoggingFeature.class);
        }
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
