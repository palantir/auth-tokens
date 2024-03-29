/*
 * (c) Copyright 2016 Palantir Technologies Inc. All rights reserved.
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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.palantir.logsafe.Preconditions;
import com.palantir.logsafe.Safe;
import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.exceptions.SafeIllegalArgumentException;
import com.palantir.logsafe.logger.SafeLogger;
import com.palantir.logsafe.logger.SafeLoggerFactory;
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
@Safe
@Value.Immutable
@ImmutablesStyle
public abstract class UnverifiedJsonWebToken {

    private static final ObjectReader READER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .readerFor(JwtPayload.class);

    private static final SafeLogger log = SafeLoggerFactory.get(UnverifiedJsonWebToken.class);

    /**
     * Returns the unverified user id, i.e., the "sub" claim, of the JWT.
     */
    @Safe
    @Value.Parameter
    public abstract String getUnverifiedUserId();

    /**
     * Returns the unverified session id, i.e. the "sid" claim, of the JWT
     * or absent if the JWT does not contain the "sid" claim.
     */
    @Safe
    @Value.Parameter
    public abstract Optional<String> getUnverifiedSessionId();

    /**
     * Returns the unverified token id, i.e. the "jti" claim, of the JWT
     * or absent if the JWT does not contain the "jti" claim.
     */
    @Safe
    @Value.Parameter
    public abstract Optional<String> getUnverifiedTokenId();

    /**
     * Returns the unverified organization id, i.e. the "org" claim, of the JWT
     * or absent if the JWT does not contain the "org" claim.
     */
    @Safe
    @Value.Parameter
    public abstract Optional<String> getUnverifiedOrganizationId();

    /**
     * Does a lower cost check on the structure of string provided
     * before attempting to create an {@link UnverifiedJsonWebToken}.
     */
    public static Optional<UnverifiedJsonWebToken> tryParse(String rawAuthHeader) {
        if (countCharacter(rawAuthHeader, '.') == 2) {
            try {
                return Optional.of(of(AuthHeader.valueOf(rawAuthHeader).getBearerToken()));
            } catch (Throwable t) {
                log.debug("Unable to process auth header.", t);
            }
        }
        return Optional.empty();
    }

    private static int countCharacter(String input, char toCount) {
        int count = 0;
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) == toCount) {
                ++count;
            }
        }
        return count;
    }

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
        String[] segments = token.getToken().split("\\.", -1);

        // Avoid creating Arg on the hot path
        if (segments.length != 3) {
            throw new SafeIllegalArgumentException(
                    "Invalid JWT: expected 3 segments", SafeArg.of("segmentsCount", segments.length));
        }

        JwtPayload payload = extractPayload(segments[1]);

        return ImmutableUnverifiedJsonWebToken.of(
                decodeUuidBytes(payload.sub),
                Optional.ofNullable(payload.sid).map(UnverifiedJsonWebToken::decodeUuidBytes),
                Optional.ofNullable(payload.jti).map(UnverifiedJsonWebToken::decodeUuidBytes),
                Optional.ofNullable(payload.org).map(UnverifiedJsonWebToken::decodeUuidBytes));
    }

    private static JwtPayload extractPayload(String payload) {
        try {
            return READER.readValue(Base64.getUrlDecoder().decode(payload));
        } catch (IllegalArgumentException | IOException e) {
            throw new SafeIllegalArgumentException("Invalid JWT: cannot parse payload", e);
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
                "Invalid JWT: cannot decode UUID, require 16 bytes",
                SafeArg.of("bytesLength", bytes.length));
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        long high = byteBuffer.getLong();
        long low = byteBuffer.getLong();
        return UuidStringConverter.toString(new UUID(high, low));
    }

    private static final class JwtPayload {

        @JsonProperty("sub")
        private byte[] sub;

        @JsonProperty("sid")
        private byte[] sid;

        @JsonProperty("jti")
        private byte[] jti;

        @JsonProperty("org")
        private byte[] org;
    }
}
