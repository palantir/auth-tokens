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

import static com.google.common.base.Preconditions.checkArgument;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.google.common.io.BaseEncoding;
import java.io.IOException;
import java.nio.ByteBuffer;
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
@Value.Style(visibility = Value.Style.ImplementationVisibility.PACKAGE, jdkOnly = true)
public abstract class UnverifiedJsonWebToken {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new GuavaModule());

    /**
     * Returns the unverified user id, i.e., the "sub" (subject) field of the JWT.
     */
    @Value.Parameter
    public abstract String getUnverifiedUserId();

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
        checkArgument(segments.length == 3, "Invalid JWT: expected 3 segments, found %s", segments.length);

        JsonWebTokenPayload payload = extractPayload(segments[1]);

        return ImmutableUnverifiedJsonWebToken.of(decodeUuidBytes(payload.getSub()));
    }

    private static JsonWebTokenPayload extractPayload(String payload) {
        try {
            return MAPPER.readValue(BaseEncoding.base64().decode(payload), JsonWebTokenPayload.class);
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
        checkArgument(bytes.length == 16, "Invalid JWT: cannot decode UUID, require 16 bytes, found %s", bytes.length);
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        long high = byteBuffer.getLong();
        long low = byteBuffer.getLong();
        return new UUID(high, low).toString();
    }

}
