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

import java.util.UUID;

/**
 * Heavily based on Jackson's 'UUIDSerializer'. Changes made have been to change the format to comply
 * with Palantir style, and make the method return a string rather than writing into a JSON processor.
 *
 * That project is Apache 2.0 licensed, but the original source contains no license header on its own,
 * so here we link to their license file.
 *
 * https://github.com/FasterXML/jackson-databind/blob/master/src/main/resources/META-INF/LICENSE
 */
final class UuidStringConverter {
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private UuidStringConverter() {}

    static String toString(UUID value) {
        final char[] ch = new char[36];
        final long msb = value.getMostSignificantBits();
        writeInt((int) (msb >>> 32), ch, 0);
        ch[8] = '-';
        writeShort((int) (msb >>> 16), ch, 9);
        ch[13] = '-';
        writeShort((int) msb, ch, 14);
        ch[18] = '-';

        final long lsb = value.getLeastSignificantBits();
        writeShort((int) (lsb >>> 48), ch, 19);
        ch[23] = '-';
        writeShort((int) (lsb >>> 32), ch, 24);
        writeInt((int) lsb, ch, 28);
        return new String(ch);
    }

    private static void writeInt(int bits, char[] ch, int offset) {
        writeShort(bits >> 16, ch, offset);
        writeShort(bits, ch, offset + 4);
    }

    private static void writeShort(int bits, char[] ch, int offset) {
        ch[offset] = HEX_CHARS[(bits >> 12) & 0xF];
        ch[offset + 1] = HEX_CHARS[(bits >> 8) & 0xF];
        ch[offset + 2] = HEX_CHARS[(bits >> 4) & 0xF];
        ch[offset + 3] = HEX_CHARS[bits & 0xF];
    }
}
