/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;

@ExtendWith(MockitoExtension.class)
final class BearerTokenLoggingFilterTest {

    private static final String USER_ID_KEY = Utilities.Key.USER_ID.getMdcKey();
    private static final String SESSION_ID_KEY = Utilities.Key.SESSION_ID.getMdcKey();
    private static final String TOKEN_ID_KEY = Utilities.Key.TOKEN_ID.getMdcKey();

    @Mock
    private ContainerRequestContext requestContext;

    private Map<String, Object> requestProperties;
    private BearerTokenLoggingFilter filter;

    @BeforeEach
    void before() {
        requestProperties = new HashMap<>();
        filter = new BearerTokenLoggingFilter();
        MDC.clear();

        lenient()
                .doAnswer(invocation -> {
                    String name = invocation.getArgument(0);
                    return requestProperties.get(name);
                })
                .when(requestContext)
                .getProperty(anyString());

        lenient()
                .doAnswer(invocation -> {
                    String name = invocation.getArgument(0);
                    Object object = invocation.getArgument(1);
                    requestProperties.put(name, object);
                    return null;
                })
                .when(requestContext)
                .setProperty(anyString(), any());
    }

    @Test
    void mdcClearedIfNoAuthHeaderProvided() {
        assertThatMdcIsCleared();
    }

    @Test
    void mdcClearedIfInvalidAuthHeaderProvided() {
        when(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("BOGUS");
        assertThatMdcIsCleared();
    }

    @Test
    void assertContextPropKeyPrefixIsStable() {
        when(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(TestConstants.AUTH_HEADER);
        filter.filter(requestContext);

        assertThat(MDC.get(USER_ID_KEY)).isEqualTo(TestConstants.USER_ID);
        assertThat(requestContext.getProperty("com.palantir.tokens.auth.userId"))
                .isEqualTo(TestConstants.USER_ID);
    }

    @Test
    void userIdInformationIsSet() {
        when(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(TestConstants.AUTH_HEADER);
        filter.filter(requestContext);

        assertThat(MDC.get(USER_ID_KEY)).isEqualTo(TestConstants.USER_ID);
        assertThat(requestContext.getProperty(Utilities.getRequestPropertyKey(USER_ID_KEY)))
                .isEqualTo(TestConstants.USER_ID);
    }

    @Test
    void sessionIdInformationIsSet() {
        when(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(TestConstants.AUTH_HEADER);
        filter.filter(requestContext);

        assertThat(MDC.get(SESSION_ID_KEY)).isEqualTo(TestConstants.SESSION_ID);
        assertThat(requestContext.getProperty(Utilities.getRequestPropertyKey(SESSION_ID_KEY)))
                .isEqualTo(TestConstants.SESSION_ID);
    }

    @Test
    void tokenIdInformationIsSet() {
        when(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(TestConstants.AUTH_HEADER);
        filter.filter(requestContext);

        assertThat(MDC.get(TOKEN_ID_KEY)).isEqualTo(TestConstants.TOKEN_ID);
        assertThat(requestContext.getProperty(Utilities.getRequestPropertyKey(TOKEN_ID_KEY)))
                .isEqualTo(TestConstants.TOKEN_ID);
    }

    private void assertThatMdcIsCleared() {
        MDC.put(USER_ID_KEY, "uid");
        MDC.put(SESSION_ID_KEY, "sid");
        MDC.put(TOKEN_ID_KEY, "tid");

        filter.filter(requestContext);

        assertThat(MDC.get(USER_ID_KEY)).isNull();
        assertThat(MDC.get(SESSION_ID_KEY)).isNull();
        assertThat(MDC.get(TOKEN_ID_KEY)).isNull();
    }
}
