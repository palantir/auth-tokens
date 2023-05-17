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
import javax.ws.rs.container.ContainerRequestContext;
import org.slf4j.MDC;

final class Utilities {

    static final String JSON_WEB_TOKEN_KEY = getRequestPropertyKey("jwt");

    static void clearMdc() {
        MDC.remove(Key.USER_ID.getMdcKey());
        MDC.remove(Key.SESSION_ID.getMdcKey());
        MDC.remove(Key.TOKEN_ID.getMdcKey());
    }

    /** Writes to both the MDC and ContainerRequestContext. */
    static void recordUnverifiedJwt(
            ContainerRequestContext requestContext, Optional<UnverifiedJsonWebToken> parsedJwt) {
        if (parsedJwt.isPresent()) {
            UnverifiedJsonWebToken jwt = parsedJwt.get();
            setUnverifiedContext(requestContext, Key.USER_ID, jwt.getUnverifiedUserId());
            setUnverifiedContext(requestContext, Key.SESSION_ID, jwt.getUnverifiedSessionId());
            setUnverifiedContext(requestContext, Key.TOKEN_ID, jwt.getUnverifiedTokenId());
            setUnverifiedContext(requestContext, Key.ORGANIZATION_ID, jwt.getUnverifiedOrganizationId());
            requestContext.setProperty(JSON_WEB_TOKEN_KEY, jwt);
        }
    }

    private static void setUnverifiedContext(ContainerRequestContext requestContext, Key key, String value) {
        MDC.put(key.getMdcKey(), value);
        requestContext.setProperty(key.getContextKey(), value);
    }

    private static void setUnverifiedContext(ContainerRequestContext requestContext, Key key, Optional<String> value) {
        if (value.isPresent()) {
            setUnverifiedContext(requestContext, key, value.get());
        }
    }

    static String getRequestPropertyKey(String key) {
        return "com.palantir.tokens.auth." + key;
    }

    enum Key {
        USER_ID("userId"),
        SESSION_ID("sessionId"),
        TOKEN_ID("tokenId"),
        ORGANIZATION_ID("organizationId");

        private final String mdc;
        private final String context;

        Key(String mdc) {
            this.mdc = mdc;
            this.context = getRequestPropertyKey(mdc);
        }

        public String getMdcKey() {
            return mdc;
        }

        public String getContextKey() {
            return context;
        }
    }

    private Utilities() {}
}
