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

package com.palantir.tokens.auth.http;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.Layout;
import com.fasterxml.jackson.annotation.JsonTypeName;
import io.dropwizard.logging.AbstractAppenderFactory;

/**
 * An {@link AppenderFactory} implementation that allows recovery of the appender
 * for use in tests.
 * <p>
 * Jetty/Dropwizard do not have an alternative scheme for grabbing the appender
 * associated with the request log, which holds onto an slf4j {@code LoggingContext}
 * but does not otherwise expose a way to get a handle on the logger itself.
 */
@JsonTypeName("mock")
public final class MockAppenderFactory extends AbstractAppenderFactory {

    public static final Appender<ILoggingEvent> MOCK_REQUEST_APPENDER = setup();

    private static Appender<ILoggingEvent> setup() {
        @SuppressWarnings("unchecked")
        Appender<ILoggingEvent> mockAppender = mock(Appender.class);
        when(mockAppender.getName()).thenReturn("MOCK");
        return mockAppender;
    }

    @Override
    public Appender<ILoggingEvent> build(LoggerContext context, String applicationName,
            Layout<ILoggingEvent> layout) {
        return MOCK_REQUEST_APPENDER;
    }

}
