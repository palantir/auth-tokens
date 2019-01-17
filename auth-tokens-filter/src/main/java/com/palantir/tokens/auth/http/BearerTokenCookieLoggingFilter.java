/*
 * (c) Copyright 2019 Palantir Technologies Inc. All rights reserved.
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

import com.palantir.tokens.auth.UnverifiedJsonWebToken;
import java.util.Optional;
import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Cookie;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

@Priority(Priorities.AUTHORIZATION)
class BearerTokenCookieLoggingFilter implements ContainerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(BearerTokenLoggingFilter.class);
    private final String cookie;

    BearerTokenCookieLoggingFilter(String cookie) {
        this.cookie = cookie;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        clearMdc();

        Cookie authCookie = requestContext.getCookies().get(cookie);
        if (authCookie == null) {
            log.debug("No auth token present in request cookies.");
            return;
        }

        Optional<UnverifiedJsonWebToken> parsedJwt = UnverifiedJsonWebToken.tryParse(authCookie.getValue());
        parsedJwt.ifPresent(jwt -> {
            setUnverifiedContext(requestContext, BearerTokenLoggingFilter.USER_ID_KEY, jwt.getUnverifiedUserId());
            jwt.getUnverifiedSessionId()
                    .ifPresent(s -> setUnverifiedContext(requestContext, BearerTokenLoggingFilter.SESSION_ID_KEY, s));
            jwt.getUnverifiedTokenId()
                    .ifPresent(s -> setUnverifiedContext(requestContext, BearerTokenLoggingFilter.TOKEN_ID_KEY, s));
        });
    }

    private static void clearMdc() {
        MDC.remove(BearerTokenLoggingFilter.USER_ID_KEY);
        MDC.remove(BearerTokenLoggingFilter.SESSION_ID_KEY);
        MDC.remove(BearerTokenLoggingFilter.TOKEN_ID_KEY);
    }

    private static void setUnverifiedContext(ContainerRequestContext requestContext, String key, String value) {
        MDC.put(key, value);
        requestContext.setProperty(getRequestPropertyKey(key), value);
    }

    public static String getRequestPropertyKey(String key) {
        return "com.palantir.tokens.auth." + key;
    }
}
