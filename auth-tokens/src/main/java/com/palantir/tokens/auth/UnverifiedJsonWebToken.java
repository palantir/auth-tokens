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


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import org.immutables.value.Value;

/**
 * Represents the parsed form of a JWT but does not verify the token signature.
 * <p>
 * The information provided by this class should not be used for any security-sensitive
 * application unless verified through some other process (e.g. by querying another
 * service known to perform validation).
 * <p>
 * An anticipated use of this class is making a best-effort user id extraction for
 * logging.
 */
@Value.Immutable
@ImmutablesStyle
public abstract class UnverifiedJsonWebToken {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new Jdk8Module());

    /**
     * Returns the unverified user id, i.e., the "sub" (subject) field of the JWT.
     */
    @Value.Parameter
    public abstract String getUnverifiedUserId();

    /**
     * Returns the unverified session id for this token, i.e. the "sid" field of the JWT
     * or absent if this token does not contain session information.
     */
    @Value.Parameter
    public abstract Optional<String> getUnverifiedSessionId();

    /**
     * Returns the unverified token id for this token, i.e. the "jti" field of the JWT
     * or absent if this token does not use the "jti" field as a unique identifier.
     */
    @Value.Parameter
    public abstract Optional<String> getUnverifiedTokenId();

    /**
     * Attempts to create an {@link UnverifiedJsonWebToken} from provided {@link BearerToken}.
     * <p>
     * The information provided by this class should not be used for any security-sensitive
     * application unless verified through some other process (e.g. by querying another
     * service known to perform validation).
     * <p>
     * An anticipated use of this class is making a best-effort user id extraction for logging.
     */
    public static UnverifiedJsonWebToken of(BearerToken token) {
        String[] segments = token.getToken().split("\\.");
        Preconditions.checkArgument(
                segments.length == 3,
                "Invalid JWT: expected 3 segments, found %s",
                segments.length);

        JsonWebTokenPayload payload = extractPayload(segments[1]);

        return ImmutableUnverifiedJsonWebToken.of(
                decodeUuidBytes(payload.getSub()),
                payload.getSid().map(UnverifiedJsonWebToken::decodeUuidBytes),
                payload.getJti().map(UnverifiedJsonWebToken::decodeUuidBytes));
    }

    private static JsonWebTokenPayload extractPayload(String payload) {
        try {
            return MAPPER.readValue(Base64.getDecoder().decode(payload), JsonWebTokenPayload.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid JWT: cannot parse payload", e);
        }
    }

    /**
     * Returns an encoded UUID from a length 16 byte array.
     * <p>
     * Palantir stores UUIDs in this format to optimize on shorter JWTs.
     */
    private static String decodeUuidBytes(byte[] bytes) {
        Preconditions.checkArgument(
                bytes.length == 16,
                "Invalid JWT: cannot decode UUID, require 16 bytes, found %s",
                bytes.length);
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        long high = byteBuffer.getLong();
        long low = byteBuffer.getLong();
        return new UUID(high, low).toString();
    }
}
