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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.config.keys.KeyTypeSupport;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.AbstractSignature;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 *
 * @author Pavel Flaska
 */
public final class EdECBuiltinSecurityProvider implements KeyTypeSupport {

    /**
     *
     */
    public EdECBuiltinSecurityProvider() {
        super();
    }

    @Override
    public boolean supports(String keyType) {
        return KeyPairProvider.SSH_ED25519.equals(keyType);
    }

    @Override
    public boolean available() {
        // todo #pf: It can be useful to introduce config property to explicitely
        // enable/disable provider. Prevent collision.
        Provider.Service ed25519factory = Security.getProvider("SunEC").getService("KeyFactory", "Ed25519");
        return ed25519factory != null;
    }

    @Override
    public Class<? extends PublicKey> getEDDSAPublicKeyType() {
        return EdECPublicKey.class;
    }

    @Override
    public Class<? extends PrivateKey> getEDDSAPrivateKeyType() {
        return EdECPrivateKey.class;
    }

    @Override
    public PublicKey generatePublicKey(byte[] seed) throws GeneralSecurityException {
        KeyFactory factory = KeyFactory.getInstance("ED25519", "SunEC");
        EdECPublicKeySpec keySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, decodeToEdECPoint(seed));
        return factory.generatePublic(keySpec);
    }

    @Override
    public PrivateKey generatePrivateKey(byte[] seed) throws GeneralSecurityException {
        EdECPrivateKeySpec keySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed);
        KeyFactory factory = KeyFactory.getInstance("ED25519", "SunEC");
        return factory.generatePrivate(keySpec);
    }

    @Override
    public PublicKeyEntryDecoder getPublicKeyEntryDecoder() {
        return Ed25519BuiltinPublicKeyDecoder.INSTANCE;
    }

    @Override
    public PrivateKeyEntryDecoder getPrivateKeyEntryDecoder() {
        return OpenSSHEd25519BuiltinPrivateKeyEntryDecoder.INSTANCE;
    }

    @Override
    public Signature getSignature() {
        // todo #pf: prototype only!
        return new AbstractSignature("Ed25519") {
            @Override
            public boolean verify(SessionContext session, byte[] sig) throws Exception {
                Map.Entry<String, byte[]> encoding = extractEncodedSignature(sig, Collections.singleton("ssh-ed25519"));

                return doVerify(encoding.getValue());
            }
        };
    }

    /**
     * Create EdECPoint from open ssh public key bytes.
     *
     * @param publicKeyBytes ed25519 OpenSSH public key bytes
     */
    static EdECPoint decodeToEdECPoint(byte[] publicKeyBytes) {
        // The BigInteger input array is assumed to be in big-endian byte-order,
        // but we've got the input in little-endian representation from open ssh
        // reader.
        //
        // References:
        // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.3
        // https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/math/BigInteger.html#%3Cinit%3E(byte%5B%5D)
        reverseBytes(publicKeyBytes);

        BigInteger y = new BigInteger(1, publicKeyBytes);
        // is x-coordinate odd?
        boolean xOdd = y.testBit(255);
        //  The y-coordinate is recovered simply by clearing xOdd bit.
        y = y.clearBit(255);

        return new EdECPoint(xOdd, y);
    }

    private static void reverseBytes(byte[] keyArray) {
        int i = 0;
        int j = keyArray.length - 1;

        while (i < j) {
            byte tmp = keyArray[i];
            keyArray[i] = keyArray[j];
            keyArray[j] = tmp;
            i++;
            j--;
        }
    }

    @Override
    public Buffer putRawPublicKey(Buffer buffer, PublicKey key) {
        EdECPublicKey edKey = ValidateUtils.checkInstanceOf(key, EdECPublicKey.class, "Not an EDDSA public key: %s", key);

        byte[] seed = edKey.getPoint().getY().toByteArray();
        reverseBytes(seed);
        buffer.putBytes(seed);

        return buffer;
    }

    @Override
    public boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2) {
        if ((k1 instanceof EdECPublicKey) && (k2 instanceof EdECPublicKey)) {
            return Objects.equals(k1, k2);
        } else {
            return false;
        }
    }

}
