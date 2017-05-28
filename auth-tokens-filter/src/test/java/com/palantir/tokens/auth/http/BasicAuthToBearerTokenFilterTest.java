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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestWrapper;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
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
    private HttpServletRequest httpServletRequest;
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
    public final void testExpectedHeader() throws Exception {
        String password = "password";
        setPassword(password);
        filter();
        assertChainRequestHasAuthHeader("Bearer " + password);
    }

    @Test
    public final void testNotInstanceOfHttpServletRequest() throws Exception {
        // servletRequestWrapper is not instanceof HttpServletRequest
        ServletRequestWrapper servletRequestWrapper = new ServletRequestWrapper(httpServletRequest);
        filter(servletRequestWrapper);
        assertFilteredRequestIs(servletRequestWrapper);  // filtered request is unchanged
    }

    @Test
    public final void testNullAuthHeader() throws Exception {
        setAuthHeader(null);
        filter();
        assertRequestUnchanged();
    }

    @Test
    public final void testAuthHeaderNotBasicAuth() throws IOException, ServletException {
        setAuthHeader("something unexpected");
        filter();
        assertRequestUnchanged();
    }

    @Test
    public final void testCannotDecode() throws IOException, ServletException {
        String encodedCreds = "not base-64 encoded";
        setBasicAuthHeader(encodedCreds);
        filter();
        assertRequestUnchanged();
    }

    @Test
    public final void testLacksColon() throws IOException, ServletException {
        String credentials = "lacks-colon";
        setCredentials(credentials);
        filter();
        assertRequestUnchanged();
    }

    private void filter() throws IOException, ServletException {
        filter(httpServletRequest);
    }

    private void filter(ServletRequest request) throws IOException, ServletException {
        tokenFilter.doFilter(request, null, chain);
    }

    private void setPassword(String password) {
        String credentials = "foo:" + password;
        setCredentials(credentials);
    }

    private void setCredentials(String credentials) {
        String encodedCreds = BASE_64_ENCODING.encode(credentials.getBytes(StandardCharsets.UTF_8));
        setBasicAuthHeader(encodedCreds);
    }

    private void setBasicAuthHeader(String encodedCreds) {
        String authHeader = "Basic " + encodedCreds;
        setAuthHeader(authHeader);
    }

    private void setAuthHeader(String authHeader) {
        when(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
    }

    private void assertChainRequestHasAuthHeader(String expectedAuthHeader) throws IOException, ServletException {
        HttpServletRequest value = (HttpServletRequest) getChainRequest();
        String actualAuthHeader = value.getHeader(HttpHeaders.AUTHORIZATION);
        assertThat(actualAuthHeader).isEqualTo(expectedAuthHeader);
    }

    private void assertRequestUnchanged() throws IOException, ServletException {
        assertFilteredRequestIs(httpServletRequest);
    }

    private void assertFilteredRequestIs(ServletRequest request) throws IOException, ServletException {
        ServletRequest chainRequest = getChainRequest();
        assertThat(chainRequest).isEqualTo(request);
    }

    private ServletRequest getChainRequest() throws IOException, ServletException {
        verify(chain).doFilter(requestArgumentCaptor.capture(), Mockito.<ServletResponse>any());
        return requestArgumentCaptor.getValue();
    }

}
