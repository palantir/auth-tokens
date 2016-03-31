/*
 * Copyright 2016 Palantir Technologies, Inc. All rights reserved.
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

package com.palantir.tokens.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.google.common.base.Preconditions;
import java.util.regex.Pattern;
import org.immutables.value.Value;

/**
 * Value class representing an authentication bearer token.
 */
@Value.Immutable
@Value.Style(visibility = Value.Style.ImplementationVisibility.PACKAGE, jdkOnly = true)
public abstract class BearerToken {

    private static final String VALIDATION_PATTERN_STRING = "^[A-Za-z0-9\\-\\._~\\+/]+=*$";
    private static final Pattern VALIDATION_PATTERN = Pattern.compile(VALIDATION_PATTERN_STRING);

    @Value.Parameter
    @JsonValue
    public abstract String getToken();

    @JsonCreator
    public static BearerToken valueOf(String token) {
        Preconditions.checkArgument(token != null, "BearerToken cannot be null");
        Preconditions.checkArgument(!token.isEmpty(), "BearerToken cannot be empty");
        Preconditions.checkArgument(VALIDATION_PATTERN.matcher(token).matches(),
                "BearerToken must match pattern " + VALIDATION_PATTERN_STRING + ": " + token);
        return ImmutableBearerToken.of(token);
    }

    @Override
    public String toString() {
        return getToken();
    }
}
