/*
 * Copyright 2017 Palantir Technologies, Inc. All rights reserved.
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

import com.palantir.tokens.auth.AuthHeader;
import com.palantir.tokens.auth.BearerToken;
import com.palantir.tokens.auth.UnverifiedJsonWebToken;
import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Attempts to extract a {@link UnverifiedJsonWebToken JSON Web Token} from the {@link ContainerRequestContext
 * request's} {@link HttpHeaders#AUTHORIZATION authorization header}, and populates the SLF4J {@link MDC} and the {@link
 * ContainerRequestContext request context} with user id, session id, and token id extracted from the JWT. This filter
 * is best-effort and does not throw an exception in case any of these steps fail.
 */
@Priority(Priorities.AUTHORIZATION)
public class BearerTokenLoggingFilter implements ContainerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(BearerTokenLoggingFilter.class);

    public static final String USER_ID_KEY = "userId";
    public static final String SESSION_ID_KEY = "sessionId";
    public static final String TOKEN_ID_KEY = "tokenId";

    @Override
    public final void filter(ContainerRequestContext requestContext) {
        clearMdc();

        String rawAuthHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (rawAuthHeader == null) {
            log.debug("No AuthHeader present on request.");
            return;
        }

        if (hasJwtStructure(rawAuthHeader)) {
            try {
                UnverifiedJsonWebToken jwt = UnverifiedJsonWebToken.of(
                        AuthHeader.valueOf(rawAuthHeader).getBearerToken());

                setUnverifiedContext(requestContext, USER_ID_KEY, jwt.getUnverifiedUserId());
                jwt.getUnverifiedSessionId().ifPresent(s -> setUnverifiedContext(requestContext, SESSION_ID_KEY, s));
                jwt.getUnverifiedTokenId().ifPresent(s -> setUnverifiedContext(requestContext, TOKEN_ID_KEY, s));
            } catch (Throwable t) {
                log.debug("Unable to process auth header.", t);
            }
        }
    }

    private void clearMdc() {
        MDC.remove(USER_ID_KEY);
        MDC.remove(SESSION_ID_KEY);
        MDC.remove(TOKEN_ID_KEY);
    }

    /**
     * Based on the structure check from {@link UnverifiedJsonWebToken#of(BearerToken)}.
     */
    private boolean hasJwtStructure(String rawAuthHeader) {
        return rawAuthHeader.split("\\.").length == 3;
    }

    private void setUnverifiedContext(ContainerRequestContext requestContext, String key, String value) {
        MDC.put(key, value);
        requestContext.setProperty(getRequestPropertyKey(key), value);
    }

    public static String getRequestPropertyKey(String key) {
        return "com.palantir.tokens.auth." + key;
    }
}
