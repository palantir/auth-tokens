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
public class BearerTokenBenchmark {

    private static final BearerToken TOKEN = BearerToken.valueOf("a".repeat(200));

    private static final BearerToken TOKEN_FIRST_CHAR_DIFFERENT = BearerToken.valueOf("b" + "a".repeat(199));
    private static final BearerToken TOKEN_LAST_CHAR_DIFFERENT = BearerToken.valueOf("a".repeat(199) + "b");

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public final boolean equals_firstCharDifferent() {
        return TOKEN.equals(TOKEN_FIRST_CHAR_DIFFERENT);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public final boolean equals_lastCharDifferent() {
        return TOKEN.equals(TOKEN_LAST_CHAR_DIFFERENT);
    }

    public static void main(String[] _args) throws Exception {
        Options options = new OptionsBuilder()
                .include(BearerTokenBenchmark.class.getSimpleName())
                .addProfiler(GCProfiler.class)
                .build();
        new Runner(options).run();
    }
}
