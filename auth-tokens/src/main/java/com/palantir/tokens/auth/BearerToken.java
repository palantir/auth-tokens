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

import static com.palantir.logsafe.Preconditions.checkArgument;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.palantir.logsafe.SafeArg;
import com.palantir.logsafe.exceptions.SafeIllegalArgumentException;
import java.security.MessageDigest;
import java.util.BitSet;
import org.immutables.value.Value;

/**
 * Value class representing an authentication bearer token.
 */
@Value.Immutable
@ImmutablesStyle
public abstract class BearerToken {

    private static final String VALIDATION_PATTERN_STRING = "^[A-Za-z0-9\\-\\._~\\+/]+=*$";
    private static final BitSet allowedCharacters = new BitSet();

    static {
        allowedCharacters.set('A', 'Z' + 1);
        allowedCharacters.set('a', 'z' + 1);
        allowedCharacters.set('0', '9' + 1);
        allowedCharacters.set('-');
        allowedCharacters.set('.');
        allowedCharacters.set('_');
        allowedCharacters.set('~');
        allowedCharacters.set('+');
        allowedCharacters.set('/');
    }

    private static final String INVALID_TOKEN_NULL_MESSAGE = "BearerToken cannot be null";
    private static final String INVALID_TOKEN_EMPTY_MESSAGE = "BearerToken cannot be empty";
    private static final String INVALID_TOKEN_PATTERN_MESSAGE = "BearerToken must match pattern";


    @Value.Parameter
    @JsonValue
    public abstract String getToken();

    // We use a hand-written getBytes() implementation for performance reasons.
    // Note that we don't need to worry about the character set (e.g., UTF-8) because
    // the set of allowable characters are single bytes.
    @Value.Derived
    @SuppressWarnings("DesignForExtension")
    byte[] getTokenAsBytes() {
        String token = getToken();
        byte[] result = new byte[token.length()];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) token.charAt(i);
        }
        return result;
    }

    @JsonCreator
    public static BearerToken valueOf(String token) {
        checkArgument(
                token != null,
                INVALID_TOKEN_NULL_MESSAGE,
                SafeArg.of("message", INVALID_TOKEN_NULL_MESSAGE));
        checkArgument(
                !token.isEmpty(),
                INVALID_TOKEN_EMPTY_MESSAGE,
                SafeArg.of("message", INVALID_TOKEN_EMPTY_MESSAGE));
        if (!isValidBearerToken(token)) {
            throw new SafeIllegalArgumentException(
                    INVALID_TOKEN_PATTERN_MESSAGE,
                    SafeArg.of("message", INVALID_TOKEN_PATTERN_MESSAGE),
                    SafeArg.of("validationPattern", VALIDATION_PATTERN_STRING));
        }
        return ImmutableBearerToken.of(token);
    }

    // Optimized implementation of the regular expression VALIDATION_PATTERN_STRING
    private static boolean isValidBearerToken(String token) {
        int length = token.length();
        int cursor = 0;

        for (; cursor < length; cursor++) {
            if (!allowedCharacters.get(token.charAt(cursor))) {
                break;
            }
        }

        // Need at least one valid character
        if (cursor == 0) {
            return false;
        }

        // Only trailing '=' is allowed after valid characters
        for (; cursor < length; cursor++) {
            if (token.charAt(cursor) != '=') {
                return false;
            }
        }

        return true;
    }

    @Override
    public final String toString() {
        return getToken();
    }

    @Override
    public final boolean equals(Object other) {
        return other != null
                && other instanceof BearerToken
                && MessageDigest.isEqual(((BearerToken) other).getTokenAsBytes(), getTokenAsBytes());
    }

    @Override
    public final int hashCode() {
        return getToken().hashCode();
    }
}
