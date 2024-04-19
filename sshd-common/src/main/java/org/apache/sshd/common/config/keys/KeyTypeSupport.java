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
package org.apache.sshd.common.config.keys;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.Ed25519JavaProvider;

/**
 *
 * @author Pavel Flaska
 */
public interface KeyTypeSupport {

    static List<KeyTypeSupport> providers() {
        List<KeyTypeSupport> providers = new ArrayList<>();
        ServiceLoader<KeyTypeSupport> instances = ServiceLoader.load(KeyTypeSupport.class);
        instances.iterator().forEachRemaining(providers::add);
        if (SecurityUtils.isEDDSACurveSupported()) {
            providers.add(new Ed25519JavaProvider());
        }
        return providers;
    }

    static KeyTypeSupport getProvider(String keyType) {
        KeyTypeSupport keyGenUtils = null;
        for (KeyTypeSupport g : KeyTypeSupport.providers()) {
            if (g.supports(keyType) && g.available()) {
                keyGenUtils = g;
                break;
            }
        }
        if (keyGenUtils != null) {
            System.out.println(keyGenUtils.getClass());
        }
        return keyGenUtils;
    }

    boolean supports(String keyType);

    boolean available();

    Class<? extends PublicKey> getEDDSAPublicKeyType();

    Class<? extends PrivateKey> getEDDSAPrivateKeyType();

    PublicKey generatePublicKey(byte[] seed) throws GeneralSecurityException;

    PrivateKey generatePrivateKey(byte[] seed) throws GeneralSecurityException;

    PublicKeyEntryDecoder getPublicKeyEntryDecoder();

    PrivateKeyEntryDecoder getPrivateKeyEntryDecoder();

    Signature getSignature();

    Buffer putRawPublicKey(Buffer buffer, PublicKey key);

    boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2);

}
