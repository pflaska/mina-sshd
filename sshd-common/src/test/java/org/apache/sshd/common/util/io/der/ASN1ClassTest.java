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
package org.apache.sshd.common.util.io.der;

import java.util.List;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class ASN1ClassTest extends JUnitTestSupport {
    private ASN1Class expected;

    public void initASN1ClassTest(ASN1Class expected) {
        this.expected = expected;
    }

    public static List<Object[]> parameters() {
        return parameterize(ASN1Class.VALUES);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void fromName(ASN1Class expected) {
        initASN1ClassTest(expected);
        String name = expected.name();
        for (int index = 1, count = name.length(); index <= count; index++) {
            assertSame(expected, ASN1Class.fromName(name), name);
            name = shuffleCase(name);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}") // NOTE: this also tests "fromTypeValue" since "fromDERValue" invokes it
    public void fromDERValue(ASN1Class expected) {
        initASN1ClassTest(expected);
        assertSame(expected, ASN1Class.fromDERValue((expected.getClassValue() << 6) & 0xFF));
    }
}
