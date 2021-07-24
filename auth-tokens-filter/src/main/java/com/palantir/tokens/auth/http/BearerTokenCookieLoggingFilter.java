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

import com.palantir.logsafe.logger.SafeLogger;
import com.palantir.logsafe.logger.SafeLoggerFactory;
import com.palantir.tokens.auth.UnverifiedJsonWebToken;
import java.util.Optional;
import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Cookie;

@Priority(Priorities.AUTHORIZATION)
class BearerTokenCookieLoggingFilter implements ContainerRequestFilter {
    private static final SafeLogger log = SafeLoggerFactory.get(BearerTokenCookieLoggingFilter.class);
    private final String cookie;

    BearerTokenCookieLoggingFilter(String cookie) {
        this.cookie = cookie;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        Utilities.clearMdc();

        Cookie authCookie = requestContext.getCookies().get(cookie);
        if (authCookie == null) {
            log.debug("No auth token present in request cookies.");
            return;
        }

        Optional<UnverifiedJsonWebToken> parsedJwt = UnverifiedJsonWebToken.tryParse(authCookie.getValue());
        Utilities.recordUnverifiedJwt(requestContext, parsedJwt);
    }
}
