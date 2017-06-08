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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utilities for handling {@link BearerToken}s.
 */
public final class BearerTokens {

    private static final Logger LOGGER = LoggerFactory.getLogger(BearerTokens.class);

    /**
     * The default file name of the file containing the API token, relative to the user's home directory.
     */
    public static final Path DEFAULT_API_TOKEN_FILE = Paths.get(".bearer.token");

    /**
     * A system property identifying the executing user's home directory.
     */
    private static final String USER_HOME_PROPERTY = "user.home";

    private BearerTokens() {}

    /**
     * Reads a token from the file at the given path. An {@link IllegalArgumentException} is thrown if the file is
     * malformed and an {@link IOException} when there is a problem reading the file.
     */
    public static BearerToken fromPath(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        if (lines.size() != 1) {
            throw new IllegalArgumentException(String.format(
                    "Invalid api token file, expected one line but found %d lines: %s", lines.size(), path));
        }
        return BearerToken.valueOf(lines.get(0));
    }

    /**
     * Attempts to read a {@link BearerToken} from the given files in order and will return the valid token from the
     * first existing and readable file, or throws if the content of this file is not a valid {@link BearerToken}.
     * Returns null if none of the files are readable.
     */
    public static Optional<BearerToken> fromPaths(List<Path> paths) {
        for (Path path : paths) {
            if (Files.isReadable(path)) {
                try {
                    LOGGER.debug("Found token file in path: {}", path);
                    return Optional.of(fromPath(path));
                } catch (IOException e) {
                    LOGGER.debug("No token file found in path: {}. Trying next path.", path);
                    // try next path
                }
            }
        }

        LOGGER.warn("No token file found in any of the configured paths: {}.", paths);
        return Optional.empty();
    }

    /**
     * Attempts to read an api token from each of the files in order and will return the first well formed token. If
     * none of the provided files contain an api token then several default locations will be checked as well. Returns
     * null if no token is found in any of the files.
     */
    public static Optional<BearerToken> fromPathsWithDefaults(List<Path> paths) {
        List<Path> pathsWithDefaults = new ArrayList<>(paths);
        pathsWithDefaults.add(Paths.get(System.getProperty(USER_HOME_PROPERTY)).resolve(DEFAULT_API_TOKEN_FILE));
        return fromPaths(pathsWithDefaults);
    }
}
