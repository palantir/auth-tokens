package com.palantir.tokens.auth.http;

import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        tokenFilter = new BasicAuthToBearerTokenFilter();
    }

    @Test
    public void testSimple() throws Exception {
        final String password = "password";
        setPassword(password);
        doFilter();
        assertRequestHasAuthHeader("Bearer " + password);
    }

    private void setPassword(String password) {
        final String authHeader = "Basic " + base64Encode("foo:" + password);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
    }

    private void doFilter() throws IOException, ServletException {
        tokenFilter.doFilter(request, null, chain);
    }

    private void assertRequestHasAuthHeader(String expectedAuthHeader) throws IOException, ServletException {
        verify(chain).doFilter(requestArgumentCaptor.capture(), Mockito.<ServletResponse>any());
        final HttpServletRequest value = requestArgumentCaptor.getValue();
        final String actualAuthHeader = value.getHeader(HttpHeaders.AUTHORIZATION);
        assertThat(actualAuthHeader, is(expectedAuthHeader));
    }

    private String base64Encode(String str) {
        return BASE_64_ENCODING.encode(str.getBytes(StandardCharsets.UTF_8));
    }
}