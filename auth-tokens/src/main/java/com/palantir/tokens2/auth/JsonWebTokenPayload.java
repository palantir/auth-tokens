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

package com.palantir.tokens2.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.util.Optional;
import org.immutables.value.Value;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonDeserialize(as = ImmutableJsonWebTokenPayload.class)
@JsonSerialize(as = ImmutableJsonWebTokenPayload.class)
@Value.Immutable
@ImmutablesStyle
public abstract class JsonWebTokenPayload {

    public abstract byte[] getSub();

    /**
     * Returns this token's session identifier (only for session tokens).
     */
    public abstract Optional<byte[]> getSid();

    /**
     * Returns this token's expiry (only for session tokens).
     */
    public abstract Optional<Long> getExp();

    /**
     * Returns this token's identifier (only for API tokens).
     */
    public abstract Optional<byte[]> getJti();


}
