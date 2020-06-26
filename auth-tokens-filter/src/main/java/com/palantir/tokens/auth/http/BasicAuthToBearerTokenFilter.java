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

import com.palantir.logsafe.Preconditions;
import com.palantir.logsafe.exceptions.SafeIllegalArgumentException;
import com.palantir.tokens.auth.AuthHeader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Objects;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.ws.rs.core.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link Filter} that replaces basic auth with a bearer token.
 * <p>
 * It assumes that the bearer token is held in the password field of the basic auth credentials. It assumes that the
 * bearer token is base-64 encoded.
 */
public class BasicAuthToBearerTokenFilter implements Filter {
    private static final Logger log = LoggerFactory.getLogger(BasicAuthToBearerTokenFilter.class);

    private static final String BASIC_AUTH_STR = "Basic";
    private static final Base64.Decoder BASE_64_ENCODING = Base64.getUrlDecoder();

    @Override
    public void init(FilterConfig _filterConfig) {}

    @Override
    public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        ServletRequest updatedRequest = addBearerTokenIfBasicAuth(request);
        chain.doFilter(updatedRequest, response);
    }

    @Override
    public void destroy() {}

    private ServletRequest addBearerTokenIfBasicAuth(ServletRequest request) {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            String rawAuthHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
            return addBearerTokenIfBasicAuth(httpRequest, rawAuthHeader);
        } else {
            log.warn("Request is not an HttpServletRequest.");
            return request;
        }
    }

    private ServletRequest addBearerTokenIfBasicAuth(HttpServletRequest request, String rawAuthHeader) {
        if (isBasicAuth(rawAuthHeader)) {
            AuthHeader authHeader;
            try {
                authHeader = base64DecodePassword(rawAuthHeader);
            } catch (IllegalArgumentException e) {
                log.warn("Could not decode password in basic auth header", e);
                return request;
            }
            return addBearerToken(request, authHeader);
        } else {
            log.debug("Auth header is not basic auth.");
            return request;
        }
    }

    private ServletRequest addBearerToken(HttpServletRequest request, final AuthHeader authHeader) {
        return new HttpServletRequestWrapper(request) {
            @Override
            public Enumeration<String> getHeaders(String name) {
                if (Objects.equals(name, HttpHeaders.AUTHORIZATION)) {
                    return Collections.enumeration(Collections.singletonList(authHeader.toString()));
                }
                return super.getHeaders(name);
            }

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
        String base64Credentials =
                rawAuthHeader.substring(BASIC_AUTH_STR.length()).trim();
        String credentials;
        try {
            credentials = new String(BASE_64_ENCODING.decode(base64Credentials), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new SafeIllegalArgumentException("Could not decode credentials from auth header", e);
        }
        Preconditions.checkArgument(credentials.contains(":"), "Credentials lack colon character (:).");
        String password = credentials.split(":", 2)[1];
        return AuthHeader.valueOf(password);
    }

    private boolean isBasicAuth(String rawAuthHeader) {
        return rawAuthHeader != null && rawAuthHeader.contains(BASIC_AUTH_STR);
    }
}
