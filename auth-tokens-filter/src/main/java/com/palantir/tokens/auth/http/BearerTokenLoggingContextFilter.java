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

import com.google.common.net.HttpHeaders;
import com.palantir.tokens.auth.AuthHeader;
import com.palantir.tokens.auth.UnverifiedJsonWebToken;
import java.io.IOException;
import java.security.Principal;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.eclipse.jetty.security.DefaultUserIdentity;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.UserIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * A {@link Filter} that inserts user information into slf4j logging context and standard HTTP request logging context.
 *
 * @deprecated Consider using {@link BearerTokenLoggingFilter} instead
 */
@Deprecated
public final class BearerTokenLoggingContextFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(BearerTokenLoggingContextFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;

            String rawAuthHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
            if (rawAuthHeader == null) {
                rawAuthHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION.toLowerCase());
            }

            if (rawAuthHeader != null) {
                try {
                    UnverifiedJsonWebToken jwt = UnverifiedJsonWebToken.of(
                            AuthHeader.valueOf(rawAuthHeader).getBearerToken());

                    // slf4j
                    MDC.put("userId", jwt.getUnverifiedUserId());

                    if (jwt.getUnverifiedSessionId().isPresent()) {
                        MDC.put("unverifiedSessionId", jwt.getUnverifiedSessionId().get());
                    }

                    if (jwt.getUnverifiedTokenId().isPresent()) {
                        MDC.put("unverifiedTokenId", jwt.getUnverifiedTokenId().get());
                    }

                    // Jetty
                    if (request instanceof org.eclipse.jetty.server.Request) {
                        Request jettyRequest = (org.eclipse.jetty.server.Request) request;

                        UserIdentity userIdentity = new DefaultUserIdentity(null,
                                new UsernamePrincipal(jwt.getUnverifiedUserId()), new String[0]);

                        jettyRequest.setAuthentication(new UserAuthentication("BEARER-TOKEN", userIdentity));
                    }

                } catch (Throwable t) {
                    log.warn("Unable to decode authorization header", t);
                }
            }
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}

    private static class UsernamePrincipal implements Principal {
        private final String userId;

        UsernamePrincipal(String userId) {
            this.userId = userId;
        }

        @Override
        public String getName() {
            return userId;
        }
    }
}
