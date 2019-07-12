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

import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.exceptions.SafeIllegalStateException;
import com.palantir.tokens.auth.BearerToken;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
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
        List<Method> superInterfaceMethods = Stream.concat(
                Stream.of(resourceInfo.getResourceMethod()),
                Arrays.stream(resourceInfo.getResourceClass().getInterfaces())
                        .flatMap(cls -> {
                            try {
                                return Stream.of(cls.getDeclaredMethod(
                                        resourceInfo.getResourceMethod().getName(),
                                        resourceInfo.getResourceMethod().getParameterTypes()));
                            } catch (NoSuchMethodException e) {
                                return Stream.empty();
                            }
                        })).collect(Collectors.toList());

        Optional<List<Parameter>> authorizationHeaderParams = superInterfaceMethods.stream()
                .map(method -> Arrays.stream(method.getParameters())
                        .filter(param -> param.getAnnotation(HeaderParam.class) != null)
                        .filter(param -> param.getAnnotation(HeaderParam.class)
                                .value()
                                .equalsIgnoreCase(HttpHeaders.AUTHORIZATION))
                        .collect(Collectors.toList()))
                .filter(paramList -> !paramList.isEmpty())
                .findFirst();

        if (authorizationHeaderParams.isPresent() && authorizationHeaderParams.get().size() > 1) {
            throw new SafeIllegalStateException(
                    "Multiple parameters annotated with @HeaderParam('Authorization')",
                    SafeArg.of("class", resourceInfo.getResourceClass()),
                    SafeArg.of("method", resourceInfo.getResourceMethod()));
        }

        if (authorizationHeaderParams.isPresent() && authorizationHeaderParams.get().size() == 1) {
            log.debug(
                    "Enabling BearerTokenLoggingFilter",
                    SafeArg.of("class", resourceInfo.getResourceClass()),
                    SafeArg.of("method", resourceInfo.getResourceMethod()));
            context.register(BearerTokenLoggingFilter.class);
            return;
        }

        Optional<List<Parameter>> cookieParams = superInterfaceMethods.stream()
                .map(method -> Arrays.stream(method.getParameters())
                        .filter(param -> param.getAnnotation(CookieParam.class) != null)
                        .filter(param -> param.getType().isAssignableFrom(BearerToken.class))
                        .collect(Collectors.toList()))
                .filter(paramList -> !paramList.isEmpty())
                .findFirst();

        if (cookieParams.isPresent() && cookieParams.get().size() > 1) {
            throw new SafeIllegalStateException(
                    "Multiple BearerToken parameters annotated with @CookieParam",
                    SafeArg.of("class", resourceInfo.getResourceClass()),
                    SafeArg.of("method", resourceInfo.getResourceMethod()));
        }

        if (cookieParams.isPresent() && cookieParams.get().size() == 1) {
            String cookieName = cookieParams.get().get(0).getAnnotation(CookieParam.class).value();
            log.debug(
                    "Enabling BearerTokenCookieLoggingFilter",
                    SafeArg.of("class", resourceInfo.getResourceClass()),
                    SafeArg.of("method", resourceInfo.getResourceMethod()));
            context.register(new BearerTokenCookieLoggingFilter(cookieName));
            return;
        }

        log.debug(
                "Setting filter to clear auth from logging information. "
                        + "Not adding BearerTokenLoggingFilter or BearerTokenCookieLoggingFilter as no "
                        + "@HeaderParam or @CookieParam annotated arguments were found.",
                SafeArg.of("class", resourceInfo.getResourceClass()),
                SafeArg.of("method", resourceInfo.getResourceMethod()));

        context.register(new BearerTokenClearingFilter());
    }
}
