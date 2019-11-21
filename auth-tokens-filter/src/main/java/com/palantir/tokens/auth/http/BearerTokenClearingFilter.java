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

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;

/**
 * Clears any token related information for logging purposes. Makes sure that if no auth is specified on an endpoint
 * none is persisted when using {@link BearerTokenLoggingFeature}
 */
@Priority(Priorities.AUTHORIZATION)
public class BearerTokenClearingFilter implements ContainerRequestFilter {
    @Override
    public final void filter(ContainerRequestContext _requestContext) {
        Utilities.clearMdc();
    }
}
