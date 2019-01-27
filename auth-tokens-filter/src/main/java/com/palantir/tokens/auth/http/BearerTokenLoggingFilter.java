/*
 * (c) Copyright 2017 Palantir Technologies Inc. All rights reserved.
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

    @Override
    public final void filter(ContainerRequestContext requestContext) {
        Utilities.clearMdc();

        String rawAuthHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (rawAuthHeader == null) {
            log.debug("No AuthHeader present on request.");
            return;
        }

        Optional<UnverifiedJsonWebToken> parsedJwt = UnverifiedJsonWebToken.tryParse(rawAuthHeader);
        Utilities.recordUnverifiedJwt(requestContext, parsedJwt);
    }
}
