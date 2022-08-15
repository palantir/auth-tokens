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

package com.palantir.tokens.auth.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
final class BasicAuthToBearerTokenFilterTest {

    private static final String AUTHORIZATION = "Authorization";

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private FilterChain chain;

    @Captor
    private ArgumentCaptor<HttpServletRequest> requestArgumentCaptor;

    private BasicAuthToBearerTokenFilter tokenFilter;

    @BeforeEach
    void before() {
        tokenFilter = new BasicAuthToBearerTokenFilter();
    }

    @Test
    void testExpectedHeader() throws Exception {
        String password = "password";
        setPassword(password);
        filter();
        assertChainRequestHasAuthHeader("Bearer " + password);
    }

    @Test
    void testNotInstanceOfHttpServletRequest() throws Exception {
        // servletRequestWrapper is not instanceof HttpServletRequest
        ServletRequestWrapper servletRequestWrapper = new ServletRequestWrapper(httpServletRequest);
        filter(servletRequestWrapper);
        assertFilteredRequestIs(servletRequestWrapper); // filtered request is unchanged
    }

    @Test
    void testNullAuthHeader() throws Exception {
        setAuthHeader(null);
        filter();
        assertRequestUnchanged();
    }

    @Test
    void testAuthHeaderNotBasicAuth() throws Exception {
        setAuthHeader("something unexpected");
        filter();
        assertRequestUnchanged();
    }

    @Test
    void testCannotDecode() throws Exception {
        String encodedCreds = "not base-64 encoded";
        setBasicAuthHeader(encodedCreds);
        filter();
        assertRequestUnchanged();
    }

    @Test
    void testLacksColon() throws Exception {
        String credentials = "lacks-colon";
        setCredentials(credentials);
        filter();
        assertRequestUnchanged();
    }

    private void filter() throws Exception {
        filter(httpServletRequest);
    }

    private void filter(ServletRequest request) throws Exception {
        tokenFilter.doFilter(request, null, chain);
    }

    private void setPassword(String password) {
        String credentials = "foo:" + password;
        setCredentials(credentials);
    }

    private void setCredentials(String credentials) {
        String encodedCreds = Base64.getUrlEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        setBasicAuthHeader(encodedCreds);
    }

    private void setBasicAuthHeader(String encodedCreds) {
        String authHeader = "Basic " + encodedCreds;
        setAuthHeader(authHeader);
    }

    private void setAuthHeader(String authHeader) {
        when(httpServletRequest.getHeader(AUTHORIZATION)).thenReturn(authHeader);
    }

    private void assertChainRequestHasAuthHeader(String expectedAuthHeader) throws Exception {
        HttpServletRequest value = (HttpServletRequest) getChainRequest();

        String actualAuthHeader = value.getHeader(AUTHORIZATION);
        assertThat(actualAuthHeader).isEqualTo(expectedAuthHeader);

        assertThat(Collections.list(value.getHeaders(AUTHORIZATION))).containsExactly(expectedAuthHeader);
    }

    private void assertRequestUnchanged() throws Exception {
        assertFilteredRequestIs(httpServletRequest);
    }

    private void assertFilteredRequestIs(ServletRequest request) throws Exception {
        ServletRequest chainRequest = getChainRequest();
        assertThat(chainRequest).isEqualTo(request);
    }

    private ServletRequest getChainRequest() throws Exception {
        verify(chain).doFilter(requestArgumentCaptor.capture(), Mockito.any());
        return requestArgumentCaptor.getValue();
    }
}
