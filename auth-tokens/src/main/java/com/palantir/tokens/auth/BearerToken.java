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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.io.BaseEncoding;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
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

    private static final String SUBJECT_FIELD = "sub";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * If the token contains a 'sub' field, as a base64 encoded UUID, return it as a String.
     * @return the 'sub' field of the JWT, if it exists
     */
    public final Optional<String> getUserIdInsecure() {
        try {
            String[] segments = getToken().split("\\.");

            if (segments.length != 3) {
                return Optional.absent();
            }

            String b64EncodedJson = segments[1];

            String json = new String(BaseEncoding.base64().decode(b64EncodedJson), StandardCharsets.UTF_8);

            JsonNode node = objectMapper.readTree(json);

            if (!node.has(SUBJECT_FIELD)) {
                return Optional.absent();
            }

            return Optional.of(uuidFromBytes(
                    BaseEncoding.base64().decode(node.get(SUBJECT_FIELD).asText())).toString());
        } catch (RuntimeException | IOException e) {
            return Optional.absent();
        }
    }

    private static UUID uuidFromBytes(byte[] bytes) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);

        long high = byteBuffer.getLong();
        long low = byteBuffer.getLong();

        return new UUID(high, low);
    }

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
    public final String toString() {
        return getToken();
    }
}
