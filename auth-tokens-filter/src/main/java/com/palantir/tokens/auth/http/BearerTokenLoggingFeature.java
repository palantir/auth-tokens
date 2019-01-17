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

import static java.util.stream.Collectors.toList;

import com.palantir.tokens.auth.BearerToken;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.List;
import javax.ws.rs.CookieParam;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.core.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class BearerTokenLoggingFeature implements DynamicFeature {
    private static final Logger log = LoggerFactory.getLogger(BearerTokenLoggingFeature.class);

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        Parameter[] parameters = resourceInfo.getResourceMethod().getParameters();

        List<Parameter> authorizationHeaderParams = Arrays.stream(parameters)
                .filter(param -> param.getAnnotation(HeaderParam.class) != null)
                .filter(param -> param.getAnnotation(HeaderParam.class)
                        .value()
                        .equalsIgnoreCase(HttpHeaders.AUTHORIZATION))
                .collect(toList());

        if (authorizationHeaderParams.size() > 1) {
            throw new IllegalStateException("Multiple parameters annotated with @HeaderParam('Authorization')");
        }

        if (authorizationHeaderParams.size() == 1) {
            log.debug("Enabling BearerTokenLoggingFilter",
                    resourceInfo.getResourceClass(),
                    resourceInfo.getResourceMethod());
            context.register(BearerTokenLoggingFilter.class);
            return;
        }

        List<Parameter> cookieParams = Arrays.stream(parameters)
                .filter(param -> param.getAnnotation(CookieParam.class) != null)
                .filter(param -> param.getType().isAssignableFrom(BearerToken.class))
                .collect(toList());

        if (cookieParams.size() > 1) {
            throw new IllegalStateException("Multiple BearerToken parameters annotated with @CookieParam");
        }

        if (cookieParams.size() == 1) {
            String cookieName = cookieParams.get(0).getAnnotation(CookieParam.class).value();
            log.debug("Enabling BearerTokenCookieLoggingFilter",
                    resourceInfo.getResourceClass(),
                    resourceInfo.getResourceMethod());
            context.register(new BearerTokenCookieLoggingFilter(cookieName));
            return;
        }

        log.debug(
                "Not adding BearerTokenLoggingFilter or BearerTokenCookieLoggingFilter as no "
                        + "@HeaderParam or @CookieParam annotated arguments were found",
                resourceInfo.getResourceClass(),
                resourceInfo.getResourceMethod());
    }
}
