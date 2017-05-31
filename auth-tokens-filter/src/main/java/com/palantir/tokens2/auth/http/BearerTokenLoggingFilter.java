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

package com.palantir.tokens2.auth.http;

import com.palantir.tokens2.auth.AuthHeader;
import com.palantir.tokens2.auth.UnverifiedJsonWebToken;
import java.util.Optional;
import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

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

        try {
            UnverifiedJsonWebToken jwt = UnverifiedJsonWebToken.of(
                    AuthHeader.valueOf(rawAuthHeader).getBearerToken());

            setUnverifiedContext(requestContext, USER_ID_KEY, jwt.getUnverifiedUserId());

            Optional<String> maybeUnverifiedSessionId = jwt.getUnverifiedSessionId();
            if (maybeUnverifiedSessionId.isPresent()) {
                setUnverifiedContext(requestContext, SESSION_ID_KEY, maybeUnverifiedSessionId.get());
            }

            Optional<String> maybeUnverifiedTokenId = jwt.getUnverifiedTokenId();
            if (maybeUnverifiedTokenId.isPresent()) {
                setUnverifiedContext(requestContext, TOKEN_ID_KEY, maybeUnverifiedTokenId.get());
            }
        } catch (Throwable t) {
            log.debug("Unable to process auth header.", t);
        }
    }

    private void clearMdc() {
        MDC.remove(USER_ID_KEY);
        MDC.remove(SESSION_ID_KEY);
        MDC.remove(TOKEN_ID_KEY);
    }

    private void setUnverifiedContext(ContainerRequestContext requestContext, String key, String value) {
        // * indicates unverified
        MDC.put(key, value + "*");
        requestContext.setProperty(getRequestPropertyKey(key), value + "*");
    }

    public static String getRequestPropertyKey(String key) {
        return "com.palantir.tokens2.auth." + key;
    }
}
