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

package com.palantir.tokens2.auth.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;
import io.dropwizard.Application;
import io.dropwizard.Configuration;
import io.dropwizard.setup.Environment;
import io.dropwizard.testing.junit.DropwizardAppRule;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import javax.servlet.DispatcherType;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.client.Client;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class BearerTokenLoggingContextFilterTests {

    private static final String USER_ID = "c393f659-0301-434e-a9c9-72304a507ffc";

    private static final String AUTH_HEADER = "Bearer "
            + "unused."
            + BaseEncoding.base64Url().omitPadding().encode(
                    "{\"sub\": \"w5P2WQMBQ06pyXIwSlB//A==\"}".getBytes(StandardCharsets.UTF_8))
            + ".unused";

    private Appender<ILoggingEvent> mockResourceAppender;

    @SuppressWarnings("unchecked")
    @Before
    public void before() {
        this.mockResourceAppender = mock(Appender.class);
        when(mockResourceAppender.getName()).thenReturn("MOCK");

        ch.qos.logback.classic.Logger resourceLog =
                (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(TestResource.class);
        resourceLog.addAppender(mockResourceAppender);
    }

    @Rule
    public final DropwizardAppRule<TestConfiguration> app = new DropwizardAppRule<>(TestApp.class,
            "src/test/resources/test-service.yml");

    @Test
    public void testBearerTokenLogging_userIdAppearsInMetaDataContext() {
        ArgumentCaptor<ILoggingEvent> resourceEvent = ArgumentCaptor.forClass(ILoggingEvent.class);

        Client client = JerseyClientBuilder.newClient();

        Response resp = client.target("http://localhost:" + app.getLocalPort())
                .path("ping")
                .request()
                .header(HttpHeaders.AUTHORIZATION, AUTH_HEADER)
                .get();
        assertThat(resp.getStatus()).isEqualTo(200);

        verify(mockResourceAppender).doAppend(resourceEvent.capture());
        assertThat(resourceEvent.getValue().getMDCPropertyMap().get("userId")).isEqualTo(USER_ID);
    }

    @Test
    public void testBearerTokenLogging_userIdAppearsInrequestLog() {
        ArgumentCaptor<ILoggingEvent> requestEvent = ArgumentCaptor.forClass(ILoggingEvent.class);

        Client client = JerseyClientBuilder.newClient();

        Response resp = client.target("http://localhost:" + app.getLocalPort())
                .path("ping")
                .request()
                .header(HttpHeaders.AUTHORIZATION, AUTH_HEADER)
                .get();
        assertThat(resp.getStatus()).isEqualTo(200);

        verify(MockAppenderFactory.MOCK_REQUEST_APPENDER, atLeastOnce()).doAppend(requestEvent.capture());
        assertThat(requestEvent.getValue().getFormattedMessage()).contains(USER_ID);
        assertThat(requestEvent.getValue().getMDCPropertyMap().get("userId")).isEqualTo(USER_ID);
    }

    @Test
    public void testBearerTokenLogging_caseInsensitiveHeaderKeys() {
        ArgumentCaptor<ILoggingEvent> requestEvent = ArgumentCaptor.forClass(ILoggingEvent.class);

        Client client = JerseyClientBuilder.newClient();

        Response resp = client.target("http://localhost:" + app.getLocalPort())
                .path("ping")
                .request()
                .header(HttpHeaders.AUTHORIZATION.toLowerCase(), AUTH_HEADER)
                .get();
        assertThat(resp.getStatus()).isEqualTo(200);

        verify(MockAppenderFactory.MOCK_REQUEST_APPENDER, atLeastOnce()).doAppend(requestEvent.capture());
        assertThat(requestEvent.getValue().getFormattedMessage()).contains(USER_ID);
        assertThat(requestEvent.getValue().getMDCPropertyMap().get("userId")).isEqualTo(USER_ID);
    }

    public static final class TestApp extends Application<TestConfiguration> {
        @Override
        public void run(TestConfiguration config, Environment env) throws Exception {
            env.servlets()
                .addFilter("BearerTokenLoggingContext", BearerTokenLoggingContextFilter.class)
                .addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), true, "/*");
            env.jersey().register(TestResource.class);
        }
    }

    public static final class TestConfiguration extends Configuration {}

    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public interface TestService {
        @GET
        @Path("ping")
        String ping();
    }

    public static final class TestResource implements TestService {
        private static final Logger log = LoggerFactory.getLogger(TestResource.class);

        @Override
        public String ping() {
            log.error("pong");
            return "pong";
        }
    }

}
