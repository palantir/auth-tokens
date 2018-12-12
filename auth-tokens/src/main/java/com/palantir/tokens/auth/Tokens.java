/*
 * Copyright 2018 Palantir Technologies, Inc. All rights reserved.
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

import java.util.BitSet;

/** Internal utility functions. */
final class Tokens {

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

    static boolean isValidBearerToken(String token) {
        return isValidBearerToken(token, 0);
    }

    // Optimized implementation of the regular expression BearerToken.VALIDATION_PATTERN_STRING
    static boolean isValidBearerToken(String token, int offset) {
        int length = token.length();
        int cursor = offset;

        for (; cursor < length; cursor++) {
            if (!allowedCharacters.get(token.charAt(cursor))) {
                break;
            }
        }

        // Need at least one valid character
        if (cursor == offset) {
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

    /**
     * Callers are required to validate the input using {@link #isValidBearerToken(String)}
     * prior to using this method.
     *
     * We use a hand-written getBytes() implementation for performance reasons.
     * Note that we don't need to worry about the character set (e.g., UTF-8) because
     * the set of allowable characters are single bytes.
     */
    static byte[] tokenValueAsBytes(String value, int offset, int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) value.charAt(offset + i);
        }
        return result;
    }

    static byte[] tokenValueAsBytes(String value) {
        return tokenValueAsBytes(value, 0, value.length());
    }

    private Tokens() {}
}
