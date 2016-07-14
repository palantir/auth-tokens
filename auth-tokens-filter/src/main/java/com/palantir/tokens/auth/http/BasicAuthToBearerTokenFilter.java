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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link Filter} that replaces basic auth with a bearer token.
 *
 * <p>It assumes that the bearer token is held in the password field of the basic auth credentials, and that it is
 * base-64 encoded.
 */
public class BasicAuthToBearerTokenFilter implements Filter {
    private static final String BASIC_AUTH_STR = "Basic";
    private static final Logger log = LoggerFactory.getLogger(BasicAuthToBearerTokenFilter.class);
    private static final BaseEncoding BASE_64_ENCODING = BaseEncoding.base64Url();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        ServletRequest updatedRequest = request;
        try {
            updatedRequest = getRequestWithToken(request);
        } catch (NullRawAuthHeaderException e) {
            // do nothing
        } catch (AuthHeaderNotBasicAuthException e) {
            log.warn("AuthHeaderNotBasicAuthException", e);
        }
        chain.doFilter(updatedRequest, response);
    }

    @Override
    public void destroy() {
    }

    private ServletRequest getRequestWithToken(ServletRequest request)
            throws AuthHeaderNotBasicAuthException, NullRawAuthHeaderException {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            String rawAuthHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
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
            AuthHeader authHeader = base64DecodePassword(rawAuthHeader);
            return getRequestWithTokenFromAuthHeader(authHeader, request);
        } else {
            throw new AuthHeaderNotBasicAuthException("Auth header is not basic auth.");
        }
    }

    private ServletRequest getRequestWithTokenFromAuthHeader(final AuthHeader authHeader, HttpServletRequest request) {
        return new HttpServletRequestWrapper(request) {
            @Override
            public String getHeader(String name) {
                if (Objects.equals(name, HttpHeaders.AUTHORIZATION)) {
                    return authHeader.toString();
                } else {
                    return super.getHeader(name);
                }
            }
        };
    }

    private AuthHeader base64DecodePassword(String rawAuthHeader) {
        String base64Credentials = rawAuthHeader.substring(BASIC_AUTH_STR.length()).trim();
        String credentials;
        try {
            credentials = new String(BASE_64_ENCODING.decode(base64Credentials), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Could not decode credentials from auth header: " + e.getMessage());
        }
        String password = credentials.split(":", 2)[1];
        return AuthHeader.valueOf(password);
    }

    private boolean isBasicAuth(String rawAuthHeader) {
        return rawAuthHeader.contains(BASIC_AUTH_STR);
    }

    static class NullRawAuthHeaderException extends Exception {
        NullRawAuthHeaderException(String message) {
            super(message);
        }
    }

    static class AuthHeaderNotBasicAuthException extends Exception {
        AuthHeaderNotBasicAuthException(String message) {
            super(message);
        }
    }
}
