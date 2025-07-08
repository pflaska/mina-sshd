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

package org.apache.sshd.common.util.security.eddsa.jdk;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;
import org.apache.sshd.common.util.security.eddsa.generic.GenericEd25519PublicKeyDecoder;
import org.apache.sshd.common.util.security.eddsa.generic.GenericOpenSSHEd25519PrivateKeyEntryDecoder;
import org.apache.sshd.common.util.security.eddsa.generic.GenericSignatureEd25519;

public class JdkBuiltInEdDSASupport implements EdDSASupport<EdECPublicKey, EdECPrivateKey> {

    public JdkBuiltInEdDSASupport() {
        super();
    }

    @Override
    public PublicKeyEntryDecoder<EdECPublicKey, EdECPrivateKey> getEDDSAPublicKeyEntryDecoder() {
        return new GenericEd25519PublicKeyDecoder<>(EdECPublicKey.class, EdECPrivateKey.class, this);
    }

    @Override
    public PrivateKeyEntryDecoder<EdECPublicKey, EdECPrivateKey> getOpenSSHEDDSAPrivateKeyEntryDecoder() {
        return new GenericOpenSSHEd25519PrivateKeyEntryDecoder<>(EdECPublicKey.class, EdECPrivateKey.class, this);
    }

    @Override
    public Signature getEDDSASigner() {
        return new GenericSignatureEd25519(SecurityUtils.EDDSA);
    }

    @Override
    public int getEDDSAKeySize(Key key) {
        return key instanceof EdECKey ? KEY_SIZE : -1;
    }

    @Override
    public Class<EdECPublicKey> getEDDSAPublicKeyType() {
        return EdECPublicKey.class;
    }

    @Override
    public Class<EdECPrivateKey> getEDDSAPrivateKeyType() {
        return EdECPrivateKey.class;
    }

    @Override
    public boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2) {
        if (!(k1 instanceof EdECPublicKey) || !(k2 instanceof EdECPublicKey)) {
            return false;
        }

        return Objects.equals(k1, k2);
    }

    @Override
    public boolean compareEDDSAPrivateKeys(PrivateKey k1, PrivateKey k2) {
        if (!(k1 instanceof EdECPrivateKey) || !(k2 instanceof EdECPrivateKey)) {
            return false;
        }

        return Objects.equals(k1, k2);
    }

    @Override
    public EdECPublicKey recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException {
        if (!(key instanceof EdECPrivateKey)) {
            throw new InvalidKeyException("Private key is not " + SecurityUtils.EDDSA);
        }
        EdECPrivateKey edDSAKey = (EdECPrivateKey) key;
        //        return (EdECPublicKey) edDSAKey.getPublicKey();
        // TODO
        return null;
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

    @Override
    public EdECPublicKey generateEDDSAPublicKey(byte[] seed) throws GeneralSecurityException {
        KeyFactory factory = KeyFactory.getInstance("ED25519", "SunEC");
        EdECPublicKeySpec keySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, decodeToEdECPoint(seed));
        return (EdECPublicKey) factory.generatePublic(keySpec);
    }

    @Override
    public EdECPrivateKey generateEDDSAPrivateKey(byte[] seed) throws GeneralSecurityException, IOException {
        EdECPrivateKeySpec keySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed);
        KeyFactory factory = KeyFactory.getInstance("ED25519", "SunEC");
        return (EdECPrivateKey) factory.generatePrivate(keySpec);
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
    public <B extends Buffer> B putRawEDDSAPublicKey(B buffer, PublicKey key) {
        EdECPublicKey edKey = ValidateUtils.checkInstanceOf(key, EdECPublicKey.class, "Not an EDDSA public key: %s", key);
        byte[] seed = edKey.getPoint().getY().toByteArray();
        reverseBytes(seed);
        buffer.putBytes(seed);

        return buffer;
    }

    @Override
    public <B extends Buffer> B putEDDSAKeyPair(B buffer, PublicKey pubKey, PrivateKey prvKey) {
        ValidateUtils.checkInstanceOf(pubKey, EdECPublicKey.class, "Not an EDDSA public key: %s", pubKey);
        ValidateUtils.checkInstanceOf(prvKey, EdECPrivateKey.class, "Not an EDDSA private key: %s", prvKey);
        throw new UnsupportedOperationException("Full SSHD-440 implementation N/A");
    }

    @Override
    public KeySpec createPublicKeySpec(EdECPublicKey publicKey) {
        return new X509EncodedKeySpec(publicKey.getEncoded());
    }

    @Override
    public KeySpec createPrivateKeySpec(EdECPrivateKey privateKey) {
        return new PKCS8EncodedKeySpec(privateKey.getEncoded());
    }

    @Override
    public byte[] getPublicKeyData(EdECPublicKey publicKey) {
        return publicKey == null ? null : publicKey.getEncoded();
    }

    @Override
    public byte[] getPrivateKeyData(EdECPrivateKey privateKey) throws IOException {
        return privateKey.getEncoded();
    }

    @Override
    public String getKeyFactoryAlgorithm() {
        return SecurityUtils.ED25519;
    }
}
