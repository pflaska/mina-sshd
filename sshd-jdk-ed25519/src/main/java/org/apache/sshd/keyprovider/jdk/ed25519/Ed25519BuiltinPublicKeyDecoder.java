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
package org.apache.sshd.keyprovider.jdk.ed25519;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.impl.AbstractPublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 *
 * @author Pavel Flaska
 */
public final class Ed25519BuiltinPublicKeyDecoder extends AbstractPublicKeyEntryDecoder<EdECPublicKey, EdECPrivateKey> {

    public static final Ed25519BuiltinPublicKeyDecoder INSTANCE = new Ed25519BuiltinPublicKeyDecoder();

    public Ed25519BuiltinPublicKeyDecoder() {
        super(EdECPublicKey.class, EdECPrivateKey.class,
              Collections.unmodifiableList(
                      Collections.singletonList(
                              KeyPairProvider.SSH_ED25519)));
    }

    @Override
    public EdECPublicKey clonePublicKey(EdECPublicKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        } else {
            return generatePublicKey(new EdECPublicKeySpec(key.getParams(), key.getPoint()));
        }
    }

    @Override
    public EdECPrivateKey clonePrivateKey(EdECPrivateKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        } else {
            return generatePrivateKey(new EdECPrivateKeySpec(key.getParams(), key.getBytes().get()));
        }
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        return SecurityUtils.getKeyPairGenerator(SecurityUtils.EDDSA);
    }

    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(SecurityUtils.EDDSA);
    }

    @Override
    public String encodePublicKey(OutputStream s, EdECPublicKey key) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public EdECPublicKey decodePublicKey(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        byte[] seed = KeyEntryResolver.readRLEBytes(keyData, 200);

        EdECPublicKeySpec keySpec = new EdECPublicKeySpec(
                NamedParameterSpec.ED25519, EdECBuiltinSecurityProvider.decodeToEdECPoint(seed));
        return (EdECPublicKey) KeyFactory.getInstance("ED25519", "SunEC").generatePublic(keySpec);
    }

    public static byte[] getSeedValue(EdECPublicKey key) {
        return key.getPoint().getY().toByteArray();
    }

}
