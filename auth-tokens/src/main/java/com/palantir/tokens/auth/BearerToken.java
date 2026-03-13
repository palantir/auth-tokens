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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.palantir.logsafe.DoNotLog;
import com.palantir.logsafe.Preconditions;
import com.palantir.logsafe.exceptions.SafeIllegalArgumentException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.BitSet;
import org.jspecify.annotations.Nullable;

/** Value class representing an authentication bearer token. */
@DoNotLog
public final class BearerToken {

    private static final BitSet ALLOWED_CHARACTERS = createAllowedCharacters();

    private static BitSet createAllowedCharacters() {
        BitSet allowedCharacters = new BitSet();
        allowedCharacters.set('A', 'Z' + 1);
        allowedCharacters.set('a', 'z' + 1);
        allowedCharacters.set('0', '9' + 1);
        allowedCharacters.set('-');
        allowedCharacters.set('.');
        allowedCharacters.set('_');
        allowedCharacters.set('~');
        allowedCharacters.set('+');
        allowedCharacters.set('/');
        return allowedCharacters;
    }

    private final String token;

    private byte @Nullable [] tokenBytes;

    private BearerToken(String token) {
        checkValidBearerToken(token);
        this.token = token;
    }

    @JsonCreator
    public static BearerToken valueOf(String token) {
        return new BearerToken(token);
    }

    @JsonValue
    @DoNotLog
    public String getToken() {
        return token;
    }

    private byte[] getTokenBytes() {
        if (tokenBytes == null) {
            tokenBytes = token.getBytes(StandardCharsets.US_ASCII);
        }
        return tokenBytes;
    }

    // Optimized validity check instead of using regular expressions
    private static void checkValidBearerToken(String token) {
        Preconditions.checkArgument(token != null, "BearerToken cannot be null");
        Preconditions.checkArgument(!token.isEmpty(), "BearerToken cannot be empty");

        int length = token.length();
        int cursor = 0;

        for (; cursor < length; cursor++) {
            if (!ALLOWED_CHARACTERS.get(token.charAt(cursor))) {
                break;
            }
        }

        // Need at least one valid character
        if (cursor == 0) {
            throw new SafeIllegalArgumentException("Invalid BearerToken");
        }

        // Only trailing '=' is allowed after valid characters
        for (; cursor < length; cursor++) {
            if (token.charAt(cursor) != '=') {
                throw new SafeIllegalArgumentException("Invalid BearerToken");
            }
        }
    }

    @Override
    @DoNotLog
    public String toString() {
        return token;
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof BearerToken bearerToken) {
            return MessageDigest.isEqual(getTokenBytes(), bearerToken.getTokenBytes());
        }
        return false;
    }

    @Override
    @DoNotLog
    public int hashCode() {
        return token.hashCode();
    }
}
