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

import com.google.common.base.Preconditions;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.immutables.value.Value;

/**
 * Represents a HTTP authentication header. This class wraps a string in the form of "Bearer [token]".
 */
@Value.Immutable
@ImmutablesStyle
// NOTE: no @JsonSerialize/@JsonDeserialize because auth headers are for use in @HeaderParam
// see: https://jersey.java.net/apidocs/latest/jersey/javax/ws/rs/HeaderParam.html
public abstract class AuthHeader {

    // https://tools.ietf.org/html/rfc2617#section-1.2 for case insensitive auth-scheme
    private static final String VALIDATION_PATTERN_STRING = "^bearer\\s+(.*)$";
    private static final Pattern VALIDATION_PATTERN =
            Pattern.compile(VALIDATION_PATTERN_STRING, Pattern.CASE_INSENSITIVE);

    @Value.Parameter
    public abstract BearerToken getBearerToken();

    /**
     * Takes the string form: "Bearer [token]" and creates a new {@link AuthHeader}. "Bearer" is necessary but is
     * case-insensitive.
     */
    public static AuthHeader valueOf(String authHeader) {
        Matcher matcher = VALIDATION_PATTERN.matcher(authHeader);
        Preconditions.checkArgument(matcher.find(),
                "Authorization Header must (case-insensitive) match pattern " + VALIDATION_PATTERN_STRING + ": "
                        + authHeader);
        BearerToken bearerToken = BearerToken.valueOf(matcher.group(1));
        return ImmutableAuthHeader.of(bearerToken);
    }

    public static AuthHeader of(BearerToken bearerToken) {
        return ImmutableAuthHeader.of(bearerToken);
    }

    /**
     * Gets the string form: "Bearer [token]".
     */
    @Override
    public final String toString() {
        return "Bearer " + getBearerToken().getToken();
    }
}
