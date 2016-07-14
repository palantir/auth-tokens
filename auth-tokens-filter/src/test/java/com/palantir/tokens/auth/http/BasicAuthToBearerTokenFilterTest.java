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

package com.palantir.tokens.auth.http;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.hamcrest.MatcherAssert;
import org.hamcrest.core.Is;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class BasicAuthToBearerTokenFilterTest {

    private static final BaseEncoding BASE_64_ENCODING = BaseEncoding.base64Url();

    @Mock
    private HttpServletRequest request;
    @Mock
    private FilterChain chain;
    @Captor
    private ArgumentCaptor<HttpServletRequest> requestArgumentCaptor;

    private BasicAuthToBearerTokenFilter tokenFilter;

    @Before
    public final void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        tokenFilter = new BasicAuthToBearerTokenFilter();
    }

    @Test
    public final void testSimple() throws Exception {
        String password = "password";
        setPassword(password);
        doFilter();
        assertRequestHasAuthHeader("Bearer " + password);
    }

    private void setPassword(String password) {
        String authHeader = "Basic " + base64Encode("foo:" + password);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
    }

    private void doFilter() throws IOException, ServletException {
        tokenFilter.doFilter(request, null, chain);
    }

    private void assertRequestHasAuthHeader(String expectedAuthHeader) throws IOException, ServletException {
        verify(chain).doFilter(requestArgumentCaptor.capture(), Mockito.<ServletResponse>any());
        HttpServletRequest value = requestArgumentCaptor.getValue();
        String actualAuthHeader = value.getHeader(HttpHeaders.AUTHORIZATION);
        MatcherAssert.assertThat(actualAuthHeader, Is.is(expectedAuthHeader));
    }

    private String base64Encode(String str) {
        return BASE_64_ENCODING.encode(str.getBytes(StandardCharsets.UTF_8));
    }
}
