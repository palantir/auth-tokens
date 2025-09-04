/*
 * (c) Copyright 2018 Palantir Technologies Inc. All rights reserved.
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

import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@Fork(1)
@Threads(1)
public class UnverifiedJsonWebTokenBenchmark {

    private static final String NOT_JWT = "NotJwt".repeat(40);
    private static final String SESSION_TOKEN = "Bearer eyJhbGciOiJFUzI1NiJ9."
            + "eyJleHAiOjE0NTk1NTIzNDksInNpZCI6IlA4WmoxRDVJVGUyNlR0Z"
            + "UsrWXVEWXc9PSIsInN1YiI6Inc1UDJXUU1CUTA2cHlYSXdTbEIvL0E9PSJ9"
            + ".XwPO_EEDVj6BBLScuf70_CH4jyI1ECmgVSoXLHpGlK-yIqm8MyUyFyNQTu8jh9kYheW-zBl64gmTnatkjjDH1A";

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public final Optional<UnverifiedJsonWebToken> parseNonJwt() {
        return UnverifiedJsonWebToken.tryParse(NOT_JWT);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public final Optional<UnverifiedJsonWebToken> parseSessionToken() {
        return UnverifiedJsonWebToken.tryParse(SESSION_TOKEN);
    }

    public static void main(String[] _args) throws Exception {
        Options options = new OptionsBuilder()
                .include(UnverifiedJsonWebTokenBenchmark.class.getSimpleName())
                .addProfiler(GCProfiler.class)
                .build();
        new Runner(options).run();
    }
}
