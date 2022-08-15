/*
 * (c) Copyright 2019 Palantir Technologies Inc. All rights reserved.
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

package com.palantir.tokens.auth.http;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

final class TestConstants {

    static final String USER_ID = UUID.randomUUID().toString();
    static final String SESSION_ID = UUID.randomUUID().toString();
    static final String TOKEN_ID = UUID.randomUUID().toString();
    static final String AUTH_HEADER = "Bearer "
            + "unused."
            + Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(("{"
                                    + "\"sub\": \"" + encodeUuid(USER_ID) + "\","
                                    + "\"sid\": \"" + encodeUuid(SESSION_ID) + "\","
                                    + "\"jti\": \"" + encodeUuid(TOKEN_ID) + "\"}")
                            .getBytes(StandardCharsets.UTF_8))
            + ".unused";

    private static String encodeUuid(String uuidString) {
        UUID uuid = UUID.fromString(uuidString);
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return Base64.getEncoder().encodeToString(bb.array());
    }

    private TestConstants() {}
}
