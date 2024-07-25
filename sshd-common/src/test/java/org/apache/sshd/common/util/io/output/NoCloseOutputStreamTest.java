/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.util.io.output;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class NoCloseOutputStreamTest extends JUnitTestSupport {
    public NoCloseOutputStreamTest() {
        super();
    }

    @Test
    void canKeepWritingAfterClose() throws IOException {
        Path dir = createTempClassFolder();
        Path file = dir.resolve(getCurrentTestName() + ".txt");
        Files.deleteIfExists(file);

        String expectedOutput = getClass().getName() + "#" + getCurrentTestName() + "@" + new Date();
        byte[] expected = expectedOutput.getBytes(StandardCharsets.UTF_8);
        try (OutputStream fileStream = Files.newOutputStream(file);
             OutputStream shielded = new NoCloseOutputStream(fileStream)) {
            int index = 0;
            for (; index < (expected.length / 2); index++) {
                shielded.close();
                shielded.write(expected[index] & 0xFF);
            }

            fileStream.write(expected, index, expected.length - index);
        }

        byte[] actual = Files.readAllBytes(file);
        String actualOutput = new String(actual, StandardCharsets.UTF_8);
        assertEquals(expectedOutput, actualOutput);
    }
}
