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

import com.google.common.base.Optional;
import com.google.common.net.HttpHeaders;
import com.palantir.tokens.auth.AuthHeader;
import com.palantir.tokens.auth.UnverifiedJsonWebToken;
import java.io.IOException;
import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

@Priority(Priorities.AUTHORIZATION)
public class BearerTokenLoggingFilter implements ContainerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(BearerTokenLoggingFilter.class);
    private static final String USER_ID_KEY = "userId";
    private static final String SESSION_ID_KEY = "sessionId";
    private static final String TOKEN_ID_KEY = "tokenId";

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        clearContext(requestContext);

        String rawAuthHeader = getRawAuthHeader(requestContext);
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
        } catch (Throwable t) {
            log.debug("Unable to process auth header.", t);
        }
    }

    private String getRawAuthHeader(ContainerRequestContext requestContext) {
        String rawAuthHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
        return rawAuthHeader != null
                ? rawAuthHeader
                : requestContext.getHeaderString(HttpHeaders.AUTHORIZATION.toLowerCase());
    }

    private void clearContext(ContainerRequestContext requestContext) {
        clearContext(requestContext, USER_ID_KEY);
        clearContext(requestContext, SESSION_ID_KEY);
        clearContext(requestContext, TOKEN_ID_KEY);
    }

    private void clearContext(ContainerRequestContext requestContext, String key) {
        MDC.remove(key);
        requestContext.removeProperty(getRequestPropertyKey(key));
    }

    private void setUnverifiedContext(ContainerRequestContext requestContext, String key, String value) {
        // * indicates unverified
        setContext(requestContext, key, value + "*");
    }

    private void setContext(ContainerRequestContext requestContext, String key, String value) {
        MDC.put(key, value);
        requestContext.setProperty(getRequestPropertyKey(key), value);
    }

    private String getRequestPropertyKey(String key) {
        return "com.palantir.tokens.auth." + key;
    }
}
