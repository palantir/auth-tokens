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

import org.immutables.value.Value;

/**
 * Represents a HTTP authentication header. This class wraps a string in the form of "Bearer [token]".
 */
@Value.Immutable
@ImmutablesStyle
// NOTE: no @JsonSerialize/@JsonDeserialize because auth headers are for use in @HeaderParam
// see: https://jersey.java.net/apidocs/latest/jersey/javax/ws/rs/HeaderParam.html
public abstract class AuthHeader {

    @Value.Parameter
    public abstract BearerToken getBearerToken();

    /**
     * Takes the string form: "Bearer [token]" and creates a new {@link AuthHeader}.
     */
    public static AuthHeader valueOf(String authHeader) {
        BearerToken bearerToken = BearerToken.valueOf(authHeader.replaceFirst("^Bearer ", ""));
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
