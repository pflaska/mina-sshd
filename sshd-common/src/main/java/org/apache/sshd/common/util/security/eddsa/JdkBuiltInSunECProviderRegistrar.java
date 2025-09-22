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

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Signature;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.security.AbstractSecurityProviderRegistrar;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class JdkBuiltInSunECProviderRegistrar extends AbstractSecurityProviderRegistrar {

    public static final String PROVIDER_CLASS = "sun.security.ec.SunEC";
    public static final String MODULE_CLASS = "org.apache.sshd.keyprovider.jdk.ed25519.JdkBuiltInEdDSASupport";

    private final AtomicReference<Boolean> supportHolder = new AtomicReference<>(null);

    public JdkBuiltInSunECProviderRegistrar() {
        super("SunEC");
    }

    @Override
    public boolean isEnabled() {
        if (SecurityUtils.isFipsMode() || !super.isEnabled()) {
            return false;
        }
        // no need to explicitly disable it.
        return true;
    }

    @Override
    public Provider getSecurityProvider() {
        try {
            return getOrCreateProvider(PROVIDER_CLASS);
        } catch (ReflectiveOperationException t) {
            Throwable e = ExceptionUtils.peelException(t);
            log.error("getSecurityProvider({}) failed ({}) to instantiate {}: {}",
                    getName(), e.getClass().getSimpleName(), PROVIDER_CLASS, e.getMessage());
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean isSecurityEntitySupported(Class<?> entityType, String name) {
        if (!isSupported()) {
            return false;
        }

        if (KeyPairGenerator.class.isAssignableFrom(entityType)
                || KeyFactory.class.isAssignableFrom(entityType)) {
            return Objects.compare(name, getName(), String.CASE_INSENSITIVE_ORDER) == 0;
        } else if (Signature.class.isAssignableFrom(entityType)) {
            return Objects.compare(SecurityUtils.CURVE_ED25519_SHA512, name, String.CASE_INSENSITIVE_ORDER) == 0;
        } else {
            return false;
        }
    }

    @Override
    public boolean isSupported() {
        Boolean supported;
        synchronized (supportHolder) {
            supported = supportHolder.get();
            if (supported != null) {
                return supported;
            }

            Class<?> clazz = ThreadUtils.resolveDefaultClass(getClass(), "java.security.interfaces.EdECKey");
            supported = clazz != null;
            supportHolder.set(supported);
        }

        return supported;
    }

    @Override
    public Optional<EdDSASupport<?, ?>> getEdDSASupport() {
        if (!isSupported()) {
            return Optional.empty();
        }
        try {
            EdDSASupport<?, ?> supportInstance;
            supportInstance = (EdDSASupport<?, ?>) Class.forName(MODULE_CLASS).getDeclaredConstructor().newInstance();
            return Optional.of(supportInstance);
        } catch (Exception ex) {
            Logger.getLogger(JdkBuiltInSunECProviderRegistrar.class.getName()).log(Level.SEVERE, null, ex);
        }
        return Optional.empty();
    }
}
