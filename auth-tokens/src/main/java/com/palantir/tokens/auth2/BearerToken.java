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

package com.palantir.tokens.auth2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.regex.Pattern;
import org.immutables.value.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Value class representing an authentication bearer token.
 */
@Value.Immutable
@ImmutablesStyle
public abstract class BearerToken {

    private static final Logger log = LoggerFactory.getLogger(BearerToken.class);

    private static final String VALIDATION_PATTERN_STRING = "^[A-Za-z0-9\\-\\._~\\+/]+=*$";
    private static final Pattern VALIDATION_PATTERN = Pattern.compile(VALIDATION_PATTERN_STRING);

    @Value.Parameter
    @JsonValue
    public abstract String getToken();

    @JsonCreator
    public static BearerToken valueOf(String token) {
        Preconditions.checkArgument(token != null, "BearerToken cannot be null");
        Preconditions.checkArgument(!token.isEmpty(), "BearerToken cannot be empty");
        if (!VALIDATION_PATTERN.matcher(token).matches()) {
            log.trace("Error parsing BearerToken, must match pattern {}: {}", VALIDATION_PATTERN_STRING, token);
            throw new IllegalArgumentException("BearerToken must match pattern " + VALIDATION_PATTERN_STRING);
        }
        return ImmutableBearerToken.of(token);
    }

    @Override
    public final String toString() {
        return getToken();
    }
}
