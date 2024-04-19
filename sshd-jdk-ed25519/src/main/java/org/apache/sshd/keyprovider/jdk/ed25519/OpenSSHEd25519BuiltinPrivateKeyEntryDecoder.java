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
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.impl.AbstractPrivateKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 *
 * @author Pavel Flaska
 */
public class OpenSSHEd25519BuiltinPrivateKeyEntryDecoder extends AbstractPrivateKeyEntryDecoder<EdECPublicKey, EdECPrivateKey> {

    public static final OpenSSHEd25519BuiltinPrivateKeyEntryDecoder INSTANCE
            = new OpenSSHEd25519BuiltinPrivateKeyEntryDecoder();

    private static final int PK_SIZE = 32;
    private static final int SK_SIZE = 32;
    private static final int KEYPAIR_SIZE = PK_SIZE + SK_SIZE;

    public OpenSSHEd25519BuiltinPrivateKeyEntryDecoder() {
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
    public EdECPrivateKey decodePrivateKey(
            SessionContext session, String keyType, FilePasswordProvider passwordProvider, InputStream keyData)
            throws IOException, GeneralSecurityException {
        if (!KeyPairProvider.SSH_ED25519.equals(keyType)) {
            throw new InvalidKeyException("Unsupported key type: " + keyType);
        }

        if (!SecurityUtils.isEdEcJdkAvailable() && !SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(SecurityUtils.EDDSA + " provider not supported");
        }

        // ed25519 bernstein naming: pk .. public key, sk .. secret key
        // we expect to find two byte arrays with the following structure (type:size):
        // [pk:32], [sk:32,pk:32]

        byte[] pk = GenericUtils.EMPTY_BYTE_ARRAY;
        byte[] keypair = GenericUtils.EMPTY_BYTE_ARRAY;
        try {
            pk = KeyEntryResolver.readRLEBytes(keyData, PK_SIZE * 2);
            keypair = KeyEntryResolver.readRLEBytes(keyData, KEYPAIR_SIZE * 2);
            if (pk.length != PK_SIZE) {
                throw new InvalidKeyException(
                        String.format(Locale.ENGLISH, "Unexpected pk size: %s (expected %s)", pk.length, PK_SIZE));
            }

            if (keypair.length != KEYPAIR_SIZE) {
                throw new InvalidKeyException(
                        String.format(Locale.ENGLISH, "Unexpected keypair size: %s (expected %s)", keypair.length,
                                KEYPAIR_SIZE));
            }

            // verify that the keypair contains the expected pk
            // yes, it's stored redundant, this seems to mimic the output structure of the keypair generation interface
            if (!Arrays.equals(pk, Arrays.copyOfRange(keypair, SK_SIZE, KEYPAIR_SIZE))) {
                throw new InvalidKeyException("Keypair did not contain the public key.");
            }

            byte[] sk = Arrays.copyOf(keypair, SK_SIZE);
            // EdECPrivateKeySpec params = EdDSANamedCurveTable.getByName(EdDSEdECPrivateKeySpecASecurityProviderUtils.CURVE_ED25519_SHA512);
            EdECPrivateKey privateKey = generatePrivateKey(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, sk));

            // the private key class contains the calculated public key (Abyte)
            // pointers to the corresponding code:
            // EdDSAPrivateKeySpec.EdDSAPrivateKeySpec(byte[], EdDSAParameterSpec): A = spec.getB().scalarMultiply(a);
            // EdDSAPrivateKey.EdDSAPrivateKey(EdDSAPrivateKeySpec): this.Abyte = this.A.toByteArray();

            // we can now verify the generated pk matches the one we read
            // if (!Arrays.equals(privateKey., pk)) {
            //     throw new InvalidKeyException("The provided pk does NOT match the computed pk for the given sk.");
            // }

            return privateKey;
        } finally {
            // get rid of sensitive data a.s.a.p
            Arrays.fill(pk, (byte) 0);
            Arrays.fill(keypair, (byte) 0);
        }
    }
}
