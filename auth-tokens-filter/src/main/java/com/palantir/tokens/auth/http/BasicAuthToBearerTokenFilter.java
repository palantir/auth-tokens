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

import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;
import com.palantir.tokens.auth.AuthHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * A {@link Filter} that TODO(asharp).
 */
public class BasicAuthToBearerTokenFilter implements Filter {
    private static final String BASIC_AUTH_STR = "Basic";
    private static final Logger log = LoggerFactory.getLogger(BasicAuthToBearerTokenFilter.class);
    private static final BaseEncoding BASE_64_ENCODING = BaseEncoding.base64Url();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        ServletRequest updatedRequest;
        try {
            updatedRequest = getRequestWithToken(request);
        } catch (NullRawAuthHeaderException e) {
            updatedRequest = request;
        } catch (AuthHeaderNotBasicAuthException e) {
            log.warn("AuthHeaderNotBasicAuthException", e);
            updatedRequest = request;
        }
        chain.doFilter(updatedRequest, response);
    }

    @Override
    public void destroy() {}

    private ServletRequest getRequestWithToken(ServletRequest request)
            throws AuthHeaderNotBasicAuthException, NullRawAuthHeaderException {
        if (request instanceof HttpServletRequest) {
            final HttpServletRequest httpRequest = (HttpServletRequest) request;
            final String rawAuthHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
            return getRequestWithTokenFromRawAuthHeader(rawAuthHeader, httpRequest);
        } else {
            throw new AuthHeaderNotBasicAuthException("Request is not an HttpServletRequest.");
        }
    }

    private ServletRequest getRequestWithTokenFromRawAuthHeader(String rawAuthHeader, HttpServletRequest request)
            throws AuthHeaderNotBasicAuthException, NullRawAuthHeaderException {
        if (rawAuthHeader == null) {
            throw new NullRawAuthHeaderException("Raw auth header is null.");
        } else if (isBasicAuth(rawAuthHeader)) {
            final AuthHeader authHeader = getAuthHeader(rawAuthHeader);
            return getRequestWithTokenFromAuthHeader(authHeader, request);
        } else {
            throw new AuthHeaderNotBasicAuthException("Auth header is not basic auth.");
        }
    }

    private ServletRequest getRequestWithTokenFromAuthHeader(final AuthHeader authHeader, HttpServletRequest request) {
        return new HttpServletRequestWrapper(request) {
            @Override
            public String getHeader(String name) {
                if(Objects.equals(name, HttpHeaders.AUTHORIZATION)) {
                    return authHeader.toString();
                } else {
                    return super.getHeader(name);
                }
            }
        };
    }

    private AuthHeader getAuthHeader(String rawAuthHeader) {
        final String password = getPassword(rawAuthHeader);
        return AuthHeader.valueOf(password);
    }

    private String getPassword(String rawAuthHeader) {
        String base64Credentials = rawAuthHeader.substring(BASIC_AUTH_STR.length()).trim();
        String credentials;
        try {
            credentials = new String(BASE_64_ENCODING.decode(base64Credentials), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Could not decode credentials from auth header: " + e.getMessage());
        }
        return credentials.split(":", 2)[1];
    }

    private boolean isBasicAuth(String rawAuthHeader) {
        return rawAuthHeader.contains(BASIC_AUTH_STR);
    }

    class NullRawAuthHeaderException extends Exception {
        public NullRawAuthHeaderException(String message) {
            super(message);
        }
    }

    class AuthHeaderNotBasicAuthException extends Exception {
        public AuthHeaderNotBasicAuthException(String message) {
            super(message);
        }
    }
}
