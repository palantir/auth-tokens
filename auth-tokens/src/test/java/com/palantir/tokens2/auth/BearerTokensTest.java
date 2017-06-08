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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public final class BearerTokensTest {

    private static final String USER_HOME_PROPERTY = "user.home";
    private static final String USER_HOME = System.getProperty(USER_HOME_PROPERTY);
    private static final BearerToken USER_HOME_TOKEN = BearerToken.valueOf("userHomeToken");

    @ClassRule
    public static final TemporaryFolder TEMP_FOLDER = new TemporaryFolder();

    @BeforeClass
    public static void beforeClass() throws IOException {
        // Override the System user home directory and write a token to the default token file
        String tempUserHome = TEMP_FOLDER.newFolder().getAbsolutePath();
        Path homeTokenPath = Paths.get(tempUserHome).resolve(BearerTokens.DEFAULT_API_TOKEN_FILE);
        Files.write(homeTokenPath, USER_HOME_TOKEN.toString().getBytes(StandardCharsets.UTF_8));
        System.setProperty(USER_HOME_PROPERTY, tempUserHome);
    }

    @AfterClass
    public static void afterClass() {
        System.setProperty(USER_HOME_PROPERTY, USER_HOME);
    }

    @Test
    public void testFromPath_validFile() throws IOException {
        String token = "apiToken";
        File file = writeTokenToFile(token);
        assertThat(BearerTokens.fromPath(file.toPath())).isEqualTo(BearerToken.valueOf(token));
    }

    @Test
    public void testFromPath_invalidFile() throws IOException {
        String token = "Bearer apiToken";
        File file = writeTokenToFile(token);

        assertThatThrownBy(() -> BearerTokens.fromPath(file.toPath()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("BearerToken must match pattern ^[A-Za-z0-9\\-\\._~\\+/]+=*$");
    }

    @Test
    public void testFromPath_invalidFileTwoLines() throws IOException {
        String token = "token1\ntoken2";
        File file = writeTokenToFile(token);

        assertThatThrownBy(() -> BearerTokens.fromPath(file.toPath()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "Invalid api token file, expected one line but found %d lines: %s",
                        2,
                        file.toPath().toAbsolutePath());
    }

    @Test
    public void testFromPaths_checkfilesInOrder() throws IOException {
        File file1 = writeTokenToFile("apiToken1");
        File file2 = writeTokenToFile("apiToken2");
        List<Path> paths = Arrays.asList(file1.toPath(), file2.toPath());
        assertThat(BearerTokens.fromPaths(paths)).contains(BearerToken.valueOf("apiToken1"));
    }

    @Test
    public void testFromPaths_nonExistingPath() throws IOException {
        File file1 = writeTokenToFile("apiToken1");
        List<Path> paths = Arrays.asList(Paths.get("bogus"), file1.toPath());
        assertThat(BearerTokens.fromPaths(paths)).contains(BearerToken.valueOf("apiToken1"));
    }

    @Test
    public void testFromPaths_noValidPaths() {
        List<Path> paths = Arrays.asList(Paths.get("foo"), Paths.get("bar"));
        assertThat(BearerTokens.fromPaths(paths)).isEmpty();
    }

    @Test
    public void testFromPathsWithDefaults_checkUserHomeLast() {
        List<Path> paths = Collections.singletonList(Paths.get("doesnt_exist"));
        assertThat(BearerTokens.fromPathsWithDefaults(paths)).contains(USER_HOME_TOKEN);
    }

    private static File writeTokenToFile(String token) throws IOException {
        File file = TEMP_FOLDER.newFile();
        Files.write(file.toPath(), token.getBytes(StandardCharsets.UTF_8));
        return file;
    }
}
