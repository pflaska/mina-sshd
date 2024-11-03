# Native


## Master files net.i2p


## Public Key Decoder

    sshd-common/src/main/java/org/apache/sshd/common/util/buffer/keys/SkED25519BufferPublicKeyParser.java
                 |  ↓  |
    sshd-common/src/main/java/org/apache/sshd/common/config/keys/impl/SkED25519PublicKeyEntryDecoder.java
     ↓  |     |  |     ↓
    sshd-common/src/main/java/org/apache/sshd/common/config/keys/u2f/SkED25519PublicKey.java
        ↓  |  |  |
    sshd-common/src/main/java/org/apache/sshd/common/util/security/eddsa/Ed25519PublicKeyDecoder.java
     ↓     ↓  ↓  ↓
    net.i2p.crypto.eddsa.EdDSAPublicKey


### Constant Only

    sshd-common/src/main/java/org/apache/sshd/common/util/security/eddsa/SignatureEd25519.java
## ..

    sshd-common/src/main/java/org/apache/sshd/common/util/security/eddsa/Ed25519PEMResourceKeyParser.java
    sshd-common/src/main/java/org/apache/sshd/common/util/security/eddsa/EdDSASecurityProviderRegistrar.java
    sshd-common/src/main/java/org/apache/sshd/common/util/security/eddsa/EdDSASecurityProviderUtils.java
    sshd-common/src/main/java/org/apache/sshd/common/util/security/eddsa/OpenSSHEd25519PrivateKeyEntryDecoder.java

**sshd-common/src/main/java/org/apache/sshd/common/util/security/eddsa/SignatureEd25519.java**

        super(EdDSAEngine.SIGNATURE_ALGORITHM);


### Test

    sshd-cli/src/test/java/org/apache/sshd/cli/SshKeyDumpMain.java
    sshd-common/src/test/java/org/apache/sshd/common/config/keys/writer/openssh/OpenSSHKeyPairResourceWriterTest.java
    sshd-common/src/test/java/org/apache/sshd/common/util/security/eddsa/EDDSAProviderTest.java
    sshd-common/src/test/java/org/apache/sshd/common/util/security/eddsa/Ed25519VectorsTest.java
    sshd-common/src/test/java/org/apache/sshd/common/util/security/eddsa/EdDSASecurityProviderRegistrarTest.java
    sshd-common/src/test/java/org/apache/sshd/server/keyprovider/SimpleGeneratorHostKeyProviderTest.java
    sshd-common/src/test/java/org/apache/sshd/util/test/CommonTestSupportUtils.java

### Ignored for now

PUTTy windows crap:

    sshd-putty/src/main/java/org/apache/sshd/putty/EdDSAPuttyKeyDecoder.java

Comment only:

    sshd-common/src/main/java/org/apache/sshd/server/keyprovider/SimpleGeneratorHostKeyProvider.java

### POM & Others

    assembly/pom.xml
    assembly/src/main/legal/notices.xml
    docs/dependencies.md
    pom.xml
    sshd-benchmarks/pom.xml
    sshd-cli/pom.xml
    sshd-common/pom.xml
    sshd-contrib/pom.xml
    sshd-core/pom.xml
    sshd-mina/pom.xml
    sshd-netty/pom.xml
    sshd-osgi/pom.xml
    sshd-putty/pom.xml
