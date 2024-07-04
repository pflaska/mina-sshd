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
package org.apache.sshd.common.util.security.eddsa;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.apache.sshd.common.config.keys.KeyTypeSupport;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.SecurityUtils;

import static org.apache.sshd.common.util.security.eddsa.EdDSASecurityProviderUtils.CURVE_ED25519_SHA512;

/**
 *
 * @author Pavel Flaska
 */
public class Ed25519JavaProvider implements KeyTypeSupport {

    public Ed25519JavaProvider() {
        super();
    }

    @Override
    public boolean supports(String keyType) {
        return KeyPairProvider.SSH_ED25519.equals(keyType);
    }

    @Override
    public boolean available() {
        return SecurityUtils.isEDDSACurveSupported();
    }

    @Override
    public Class<? extends PublicKey> getEDDSAPublicKeyType() {
        return EdDSAPublicKey.class;
    }

    @Override
    public Class<? extends PrivateKey> getEDDSAPrivateKeyType() {
        return EdDSAPrivateKey.class;
    }

    @Override
    public PublicKey generatePublicKey(byte[] seed) throws GeneralSecurityException {
        EdDSAParameterSpec params = EdDSANamedCurveTable.getByName(CURVE_ED25519_SHA512);
        EdDSAPublicKeySpec keySpec = new EdDSAPublicKeySpec(seed, params);
        KeyFactory factory = SecurityUtils.getKeyFactory(SecurityUtils.EDDSA);

        return factory.generatePublic(keySpec);
    }

    @Override
    public PrivateKey generatePrivateKey(byte[] seed) throws GeneralSecurityException {
        EdDSAParameterSpec params = EdDSANamedCurveTable.getByName(CURVE_ED25519_SHA512);
        EdDSAPrivateKeySpec keySpec = new EdDSAPrivateKeySpec(seed, params);
        KeyFactory factory = SecurityUtils.getKeyFactory(SecurityUtils.EDDSA);

        return factory.generatePrivate(keySpec);
    }

    @Override
    public PublicKeyEntryDecoder getPublicKeyEntryDecoder() {
        return Ed25519PublicKeyDecoder.INSTANCE;
    }

    @Override
    public PrivateKeyEntryDecoder getPrivateKeyEntryDecoder() {
        return OpenSSHEd25519PrivateKeyEntryDecoder.INSTANCE;

    }

    @Override
    public Signature getSignature() {
        Signature s = EdDSASecurityProviderUtils.getEDDSASignature();
        System.out.println("Signature: " + s);
        return s;
    }

    @Override
    public Buffer putRawPublicKey(Buffer buffer, PublicKey key) {
        ValidateUtils.checkTrue(SecurityUtils.isEDDSACurveSupported(), SecurityUtils.EDDSA + " not supported");
        EdDSAPublicKey edKey = ValidateUtils.checkInstanceOf(key, EdDSAPublicKey.class, "Not an EDDSA public key: %s", key);
        byte[] seed = Ed25519PublicKeyDecoder.getSeedValue(edKey);
        ValidateUtils.checkNotNull(seed, "No seed extracted from key: %s", edKey.getA());
        buffer.putBytes(seed);
        return buffer;
    }

    @Override
    public boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2) {
        return EdDSASecurityProviderUtils.compareEDDSAPPublicKeys(k1, k2);
    }

}
