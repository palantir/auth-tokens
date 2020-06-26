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
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.MDC;

@RunWith(MockitoJUnitRunner.class)
public final class BearerTokenLoggingFilterTest {

    private static final String USER_ID_KEY = Utilities.Key.USER_ID.getMdcKey();
    private static final String SESSION_ID_KEY = Utilities.Key.SESSION_ID.getMdcKey();
    private static final String TOKEN_ID_KEY = Utilities.Key.TOKEN_ID.getMdcKey();

    @Mock
    private ContainerRequestContext requestContext;

    private Map<String, Object> requestProperties;

    private BearerTokenLoggingFilter filter = new BearerTokenLoggingFilter();

    @Before
    public void before() {
        requestProperties = new HashMap<>();
        MDC.clear();

        doAnswer(invocation -> {
                    Object[] args = invocation.getArguments();
                    return requestProperties.get(args[0]);
                })
                .when(requestContext)
                .getProperty(anyString());

        doAnswer(invocation -> {
                    Object[] args = invocation.getArguments();
                    requestProperties.put((String) args[0], args[1]);
                    return null;
                })
                .when(requestContext)
                .setProperty(anyString(), anyObject());
    }

    @Test
    public void mdcClearedIfNoAuthHeaderProvided() {
        assertThatMdcIsCleared();
    }

    @Test
    public void mdcClearedIfInvalidAuthHeaderProvided() {
        when(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("BOGUS");
        assertThatMdcIsCleared();
    }

    @Test
    public void assertContextPropKeyPrefixIsStable() {
        when(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(TestConstants.AUTH_HEADER);
        filter.filter(requestContext);

        assertThat(MDC.get(USER_ID_KEY)).isEqualTo(TestConstants.USER_ID);
        assertThat(requestContext.getProperty("com.palantir.tokens.auth.userId"))
                .isEqualTo(TestConstants.USER_ID);
    }

    @Test
    public void userIdInformationIsSet() {
        when(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(TestConstants.AUTH_HEADER);
        filter.filter(requestContext);

        assertThat(MDC.get(USER_ID_KEY)).isEqualTo(TestConstants.USER_ID);
        assertThat(requestContext.getProperty(Utilities.getRequestPropertyKey(USER_ID_KEY)))
                .isEqualTo(TestConstants.USER_ID);
    }

    @Test
    public void sessionIdInformationIsSet() {
        when(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(TestConstants.AUTH_HEADER);
        filter.filter(requestContext);

        assertThat(MDC.get(SESSION_ID_KEY)).isEqualTo(TestConstants.SESSION_ID);
        assertThat(requestContext.getProperty(Utilities.getRequestPropertyKey(SESSION_ID_KEY)))
                .isEqualTo(TestConstants.SESSION_ID);
    }

    @Test
    public void tokenIdInformationIsSet() {
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
