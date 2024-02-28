package pq.saml.benchmarks;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.spec.*;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.security.impl.SAMLExtraSignatureProfileValidator;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.encryption.support.*;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

/**
 * A helper class containing various static functions used for manipulating and processing XML/SAML objects
 */
public class Util
{

    private static final Logger LOG = LoggerFactory.getLogger(Util.class);

    /**
     * Builds an instance of a SAML object from a class.
     * @param clazz Template class
     * @return
     * @param <T>
     */
    public static <T> T buildSAMLObject(final Class<T> clazz) {
        T obj = null;
        QName name = null;
        try {
            name = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }

        obj = (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(name).buildObject(name);

        return obj;
    }

    public static String getSAMLObjectString(final XMLObject obj) {
        Element el = obj.getDOM();
        //if (obj instanceof SignableSAMLObject && ((SignableSAMLObject) obj).isSigned() && obj.getDOM() != null) {
        if (obj.getDOM() != null) {
            el = obj.getDOM();
        } else {
            try {
                Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(obj);
                out.marshall(obj);
                el = obj.getDOM();

            } catch (MarshallingException e) {
                LOG.error(e.getMessage(), e);
            }
        }
        return SerializeSupport.prettyPrintXML(el);
    }

    /**
     * This function initializes the OpenSAML library.
     */
    public static void initOpenSAML() {
        XMLObjectProviderRegistry registry = new XMLObjectProviderRegistry();
        ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
        registry.setParserPool(Util.getParserPool());
        LOG.info("init saml");
        try {
            InitializationService.initialize();
            LOG.info("initialized opensaml");
        } catch (InitializationException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Another OpenSAML initialization function.
     * @return
     */
    private static ParserPool getParserPool() {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(100);
        parserPool.setCoalescing(true);
        parserPool.setIgnoreComments(true);
        parserPool.setIgnoreElementContentWhitespace(true);
        parserPool.setNamespaceAware(true);
        parserPool.setExpandEntityReferences(false);
        parserPool.setXincludeAware(false);

        final Map<String, Boolean> features = new HashMap<String, Boolean>();
        features.put("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
        features.put("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
        features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
        features.put("http://apache.org/xml/features/validation/schema/normalized-value", Boolean.FALSE);
        features.put("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);

        parserPool.setBuilderFeatures(features);
        parserPool.setBuilderAttributes(new HashMap<String, Object>());

        try {
            parserPool.initialize();
        } catch (ComponentInitializationException e) {
            LOG.error(e.getMessage(), e);
        }
        return parserPool;
    }

    /**
     * Verifies the standard signature of a SAML object. The method assumes the public key used for signature verification is
     * in a X509 certificate inside <KeyInfo>.
     * @param object SAML object that is going to be verified
     * @throws SignatureException in case anything is wrong with the signature
     *
     */
    private static void verifySAMLSignature(SignableSAMLObject object) throws SignatureException {
        Signature signature = object.getSignature();

        if (signature == null) {
            throw new SignatureException("Signature element is null.");
        }

        //Verifies if the signature satisfies the SAML standard. E.g. is enveloped and no other transforms are used.
        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
        validator.validate(signature);

        //Retrieves the public key from the KeyInfo and verifies the actual XML signature.
        Credential credential = new BasicX509Credential(Util.extractCertificateFromSignature(signature));
        SignatureValidator.validate(signature, credential);
    }

    /**
     * Verifies the extra signature of a SAML object. The method assumes the public key used for signature verification is
     * in a X509 certificate inside <KeyInfo>.
     * The extra signature is an immediate child of <Extensions> and contains an extra XPath transformation to remove
     * the classical signature before hashing.
     * This function also needs to use a modified SAML verifier to allow the transformation to be present.
     * @param object SAML object that is going to be verified. The function is only implemented for SAML objects which
     *               implement the StatusResponseType or RequestAbstractType interfaces. This is because we need a SAML
     *               object which contains <Extensions>.
     * @throws SignatureException in case anything is wrong with the signature
     *
     */
    private static void verifyExtraSAMLSignature(SignableSAMLObject object) throws SignatureException {
        Extensions extensions = null;

        //Check if the object has Extensions
        if (object instanceof StatusResponseType) {
            extensions = ((StatusResponseType)object).getExtensions();
        } else if (object instanceof RequestAbstractType) {
            extensions = ((RequestAbstractType)object).getExtensions();
        } else {
            throw new SignatureException("Object is not an instance of StatusResponseType or RequestAbstractType.");
        }

        //SAML object supports extensions but the Extensions element is empty. Nothing to verify.
        if (extensions == null) {
            throw new SignatureException("Extensions is null. No signature found.");
        }

        //Select the first (and should be the only) <Signature> inside <Extensions>
        List<XMLObject> signaturesInExtensions = extensions.getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME);
        if (signaturesInExtensions.isEmpty()) {
            throw new SignatureException("No signature inside Extensions.");
        }
        if (signaturesInExtensions.size() > 1) {
            throw new SignatureException("More than 1 signature inside Extensions.");
        }

        Signature extraSignature = (Signature) signaturesInExtensions.get(0);

        if (extraSignature == null) {
            throw new SignatureException("Signature element is null.");
        }

        /* Verifies if the Signature element is conformant with SAML standards with exception that it is not a direct
         child of the root but it is a child of Extensions. Also, it allows the additional XPath transform.
         */

        SAMLExtraSignatureProfileValidator validator = new SAMLExtraSignatureProfileValidator();
        validator.validate(extraSignature);

        //Retrieves the public key from the KeyInfo and verifies the actual XML signature.
        Credential credential = new BasicX509Credential(Util.extractCertificateFromSignature(extraSignature));
        SignatureValidator.validate(extraSignature, credential);
    }

    /**
     * Creates a X509Certificate object from a base64 encoded string.
     * @param certString String of a base64 encoded X509 certificate.
     * @return
     * @throws RuntimeException
     */
    private static X509Certificate createCertificateFromString(String certString) throws RuntimeException {
        X509Certificate cert = null;
        CertificateFactory factory = null;
        try {
            factory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(certString)));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        return cert;
    }

    /**
     * Retrieves a X509 certificate from a <KeyInfo> element.
     * @param keyInfo
     * @return
     */
    private static X509Certificate getCertificateFromKeyInfo(KeyInfo keyInfo) {
        String certString = null;
        try {
            if (keyInfo == null) {
                throw new NullPointerException();
            }
            certString = keyInfo.getX509Datas().get(0).getX509Certificates().get(0).getValue();
            if (certString == null) {
                throw new NullPointerException();
            }
        } catch (NullPointerException e) {
            throw new RuntimeException("Certificate not found in the KeyInfo.");
        }

        return Util.createCertificateFromString(certString);
    }

    /**
     * Retrieves a X509 certificate from a <Signature> element which has a <KeyInfo> child
     * @param signature
     * @return
     * @throws RuntimeException
     */
    private static X509Certificate extractCertificateFromSignature(Signature signature) throws RuntimeException {
        return Util.getCertificateFromKeyInfo(signature.getKeyInfo());
    }

    /**
     * Method for verifying SAML message signatures.
     * @param message SAML message to be verified
     * @param isHybrid Validate in hybrid mode or not.
     */
    public static void verifyMessageSignature(SignableSAMLObject message, boolean isHybrid)
    {
        try
        {
            if (isHybrid)
            {
                Util.verifyExtraSAMLSignature(message);
            }
            Util.verifySAMLSignature(message);
        }
        catch (SignatureException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method for signing SAML messages.
     * @param message SAML message to be signed.
     * @param isHybrid Sign using hybrid separate signature.
     * @param keyPairs Array of KeyPairs to be used for signing.
     * @param certificates Array of public key certificates corresponding to the keypairs.
     */
    public static void signSAMLMessage(SignableSAMLObject message, boolean isHybrid, KeyPair[] keyPairs, X509Certificate[] certificates)
    {
        org.opensaml.xmlsec.signature.Signature signature = Util.buildSAMLObject(org.opensaml.xmlsec.signature.Signature.class);
        X509Certificate cert = certificates[0];
        Credential cred = new BasicCredential(keyPairs[0].getPublic(), keyPairs[0].getPrivate());

        signature.setSigningCredential(cred);
        signature.setSignatureAlgorithm(getXMLSigAlgName(keyPairs[0].getPublic()));
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        //Generate KeyInfo
        X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
        factory.setEmitEntityCertificate(true);
        KeyInfo keyInfo = null;
        X509Credential x509cred = new BasicX509Credential(cert);
        try
        {
            keyInfo = factory.newInstance().generate(x509cred);
        }
        catch (SecurityException e)
        {
            throw new RuntimeException(e);
        }

        signature.setKeyInfo(keyInfo);

        //Create an extra signature over the document that is inserted into the Extensions
        //Note that the classical signature prepared before is not yet done and the signing takes process after the extra signature signing.
        if (isHybrid)
        {
            X509Certificate extraCert = certificates[1];
            Credential extraCred = new BasicCredential(keyPairs[1].getPublic(), keyPairs[1].getPrivate());

            //fix for SAML benchmark. AuthnRequest already has KEM certificates inside extensions so we dont overwrite them.
            Extensions extensions = null;
            boolean isResponse = false;
            if (message instanceof AuthnRequest)
            {
                extensions = ((AuthnRequest) message).getExtensions();
            }
            else
            {
                extensions = Util.buildSAMLObject(Extensions.class);
                isResponse = true;
            }

            org.opensaml.xmlsec.signature.Signature extraSignature = Util.buildSAMLObject(org.opensaml.xmlsec.signature.Signature.class);
            extraSignature.setSignatureAlgorithm(getXMLSigAlgName(keyPairs[1].getPublic()));
            extraSignature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            extraSignature.setSigningCredential(extraCred);

            //We need to reference the signed message. For "standard" signature this is done automatically by calling message.setSignature()
            SAMLObjectContentReference reference = new SAMLObjectContentReference(message, true);
            reference.setDigestAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA512);
            extraSignature.getContentReferences().add(reference);

            //insert KeyInfo for the extra signature.
            KeyInfo extraKeyInfo = null;
            X509Credential extraX509cred = new BasicX509Credential(extraCert);
            try
            {
                extraKeyInfo = factory.newInstance().generate(extraX509cred);
            }
            catch (SecurityException e)
            {
                throw new RuntimeException(e);
            }
            extraSignature.setKeyInfo(extraKeyInfo);

            extensions.getUnknownXMLObjects().add(extraSignature); //add signature element into extensions

            //if it is Response we need to set Extensions since they dont exist prior
            if (isResponse)
            {
                ((Response) message).setExtensions(extensions);
            }

            try
            {
                //Marshalling is needed to calculate the references etc.
                XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(message).marshall(message);
                org.opensaml.xmlsec.signature.support.Signer.signObject(extraSignature); //create the extra signature
            }
            catch (SignatureException e)
            {
                throw new RuntimeException(e);
            }
            catch (MarshallingException e)
            {
                throw new RuntimeException(e);
            }
        }

        //add the classical signature and marshall
        message.setSignature(signature);
        SAMLObjectContentReference reference = (SAMLObjectContentReference) signature.getContentReferences().get(0);
        reference.setDigestAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA512);
        try
        {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(message).marshall(message);
            org.opensaml.xmlsec.signature.support.Signer.signObject(signature);
        }
        catch (MarshallingException e)
        {
            throw new RuntimeException(e);
        }
        catch (SignatureException e)
        {
            throw new RuntimeException(e);
        }
    }


    /**
     * Method for encrypting Assertions.
     * @param assertion Assertion to be encrypted.
     * @param isHybrid Do we want hybrid XML PKE encryption?
     * @param certificates Array of encryption certificates (containing the encryption public key).
     * @return
     */
    public static EncryptedAssertion encryptAssertion(Assertion assertion, boolean isHybrid, X509Certificate[] certificates)
    {
        //choose symmetric cipher (AES-256-GCM)
        DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
        encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);

        //setup how to encrypt the AES key
        Credential cred = new BasicX509Credential(certificates[0]);
        KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
        keyEncryptionParameters.setEncryptionCredential(cred);
        keyEncryptionParameters.setAlgorithm(getXMLEncAlgName(certificates[0].getPublicKey()));

        //set that the encryption certificate is included.
        X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
        factory.setEmitEntityCertificate(true);
        keyEncryptionParameters.setKeyInfoGenerator(factory.newInstance());

        org.opensaml.saml.saml2.encryption.Encrypter encrypter = new org.opensaml.saml.saml2.encryption.Encrypter(encryptionParameters, keyEncryptionParameters);
        encrypter.setKeyPlacement(org.opensaml.saml.saml2.encryption.Encrypter.KeyPlacement.INLINE);

        EncryptedAssertion encryptedAssertion = null;
        try
        {
            //encrypt for the first time
            encryptedAssertion = encrypter.encrypt(assertion);

            //encrypt for the second time if hybrid
            if (isHybrid)
            {
                encryptionParameters = new DataEncryptionParameters();
                encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
                keyEncryptionParameters = new KeyEncryptionParameters();
                cred = new BasicX509Credential(certificates[1]);
                keyEncryptionParameters.setEncryptionCredential(cred);
                keyEncryptionParameters.setAlgorithm(getXMLEncAlgName(certificates[1].getPublicKey()));
                keyEncryptionParameters.setKeyInfoGenerator(factory.newInstance());
                encrypter = new org.opensaml.saml.saml2.encryption.Encrypter(encryptionParameters, keyEncryptionParameters);
                encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
                encryptedAssertion = encrypter.encrypt(encryptedAssertion);
                encryptedAssertion.getEncryptedData().setMimeType(EncryptionConstants.MIME_TYPE_LAYERED_ENCRYPTED_ASSERTION); //set the MIME type for the outer layer
            }
        }
        catch (EncryptionException e)
        {
            throw new RuntimeException(e);
        }

        return encryptedAssertion;
    }

    /**
     * Method for decrypting EncryptedAssertions.
     * @param encryptedAssertion EncryptedAssertion to be decrypted.
     * @param keyPairs Array of keypairs for decryption.
     * @return
     */
    public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, KeyPair[] keyPairs)
    {
        Assertion decryptedAssertion = null;
        Credential cred = null;
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = null;
        Decrypter decrypter = null;
        try
        {
            //detect if it hybrid encryption based on the MIME type.
            if (encryptedAssertion.getEncryptedData().getMimeType() == EncryptionConstants.MIME_TYPE_LAYERED_ENCRYPTED_ASSERTION)
            {
                cred = new BasicCredential(keyPairs[1].getPublic(), keyPairs[1].getPrivate());
                keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(cred);
                decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
                encryptedAssertion = decrypter.decryptLayer(encryptedAssertion);
            }

            cred = new BasicCredential(keyPairs[0].getPublic(), keyPairs[0].getPrivate());
            keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(cred);
            decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());

            decryptedAssertion = decrypter.decrypt(encryptedAssertion);

        }
        catch (DecryptionException e)
        {
            throw new RuntimeException(e);
        }

        return decryptedAssertion;
    }

    /**
     * Generate a dummy certificate.
     * @param publicKey Public key inserted into the certificate
     * @param signingKeyPair Keypair used to sign the certificate.
     * @return
     */
    public static X509Certificate generateCertificate(PublicKey publicKey, KeyPair signingKeyPair)
    {
        String subjectName = "Example subject";

        String provider = "BC";
        String signatureAlgorithm = signingKeyPair.getPrivate().getAlgorithm();

        //for classical algorithms we need to specify the signature algorithms as there are many options for "RSA" and "ECDSA"
        if (signatureAlgorithm.equals("RSA")) {
            signatureAlgorithm = "SHA512withRSA";
        }
        if (signatureAlgorithm.equals("ECDSA")) {
            int curveBits = ((ECPublicKey)signingKeyPair.getPublic()).getQ().getCurve().getFieldSize();
            //use SHA2-512 for P-521
            if (curveBits == 521) {
                signatureAlgorithm = "SHA512withECDSA";
            } else {
                signatureAlgorithm = "SHA256withECDSA";
            }

        }

        X500Name issuer = new X500Name("CN=" + subjectName);
        BigInteger serial = BigInteger.valueOf(5);
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 365);
        X500Name subject = new X500Name("CN=" + subjectName);
        X509Certificate cert = null;

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKey);

        try
        {
            X509CertificateHolder certHolder = certificateBuilder.build(new JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider).build(signingKeyPair.getPrivate()));
            cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        }
        catch (OperatorCreationException | CertificateException e)
        {
            throw new RuntimeException(e);
        }
        return cert;
    }

    /**
     * Method for generating keypair based on the algorithm names.
     * @param algName
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateKeyPair(String algName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator generator = null;
        switch (algName)
        {
            case "RSA3072":
                generator = KeyPairGenerator.getInstance("RSA", "BC");
                generator.initialize(3072, secureRandom);
                break;
            case "RSA15360":
                generator = KeyPairGenerator.getInstance("RSA", "BC");
                generator.initialize(15360, secureRandom);
                break;
            case "ECDSAP256":
                generator = KeyPairGenerator.getInstance("ECDSA", "BC");
                generator.initialize(new ECGenParameterSpec("P-256"), secureRandom);
                break;
            case "ECDSAP521":
                generator = KeyPairGenerator.getInstance("ECDSA", "BC");
                generator.initialize(new ECGenParameterSpec("P-521"), secureRandom);
                break;
            case "DILITHIUM2":
                generator = KeyPairGenerator.getInstance("Dilithium", "BC");
                generator.initialize(DilithiumParameterSpec.dilithium2, secureRandom);
                break;
            case "DILITHIUM5":
                generator = KeyPairGenerator.getInstance("Dilithium", "BC");
                generator.initialize(DilithiumParameterSpec.dilithium5, secureRandom);
                break;
            case "FALCON512":
                generator = KeyPairGenerator.getInstance("Falcon", "BC");
                generator.initialize(FalconParameterSpec.falcon_512, secureRandom);
                break;
            case "FALCON1024":
                generator = KeyPairGenerator.getInstance("Falcon", "BC");
                generator.initialize(FalconParameterSpec.falcon_1024, secureRandom);
                break;
            case "SPHINCS128":
                generator = KeyPairGenerator.getInstance("SPHINCSPlus", "BC");
                generator.initialize(SPHINCSPlusParameterSpec.sha2_128s, secureRandom);
                break;
            case "SPHINCS256":
                generator = KeyPairGenerator.getInstance("SPHINCSPlus", "BC");
                generator.initialize(SPHINCSPlusParameterSpec.sha2_256s, secureRandom);
                break;
            case "MLDSA44andECDSAP256":
                generator = KeyPairGenerator.getInstance("MLDSA44andECDSAP256", "BC");
                generator.initialize(null, secureRandom);
                break;
            case "MLDSA87andECDSAP384":
                generator = KeyPairGenerator.getInstance("MLDSA87andECDSAP384", "BC");
                generator.initialize(null, secureRandom);
                break;
            case "MLDSA87andECDSAP521":
                generator = KeyPairGenerator.getInstance("MLDSA87andECDSAP521", "BC");
                generator.initialize(null, secureRandom);
                break;
            case "Falcon512andECDSAP256":
                generator = KeyPairGenerator.getInstance("Falcon512andECDSAP256", "BC");
                generator.initialize(null, secureRandom);
                break;
            case "Falcon1024andECDSAP521":
                generator = KeyPairGenerator.getInstance("Falcon1024andECDSAP521", "BC");
                generator.initialize(null, secureRandom);
                break;
            case "KYBER512":
                generator = KeyPairGenerator.getInstance("Kyber", "BCPQC");
                generator.initialize(KyberParameterSpec.kyber512, secureRandom);
                break;
            case "KYBER1024":
                generator = KeyPairGenerator.getInstance("Kyber", "BCPQC");
                generator.initialize(KyberParameterSpec.kyber1024, secureRandom);
                break;
            case "CMCE1":
                generator = KeyPairGenerator.getInstance("CMCE", "BCPQC");
                generator.initialize(CMCEParameterSpec.mceliece348864, secureRandom);
                break;
            case "CMCE5":
                generator = KeyPairGenerator.getInstance("CMCE", "BCPQC");
                generator.initialize(CMCEParameterSpec.mceliece6688128, secureRandom);
                break;
            case "BIKE1":
                generator = KeyPairGenerator.getInstance("BIKE", "BCPQC");
                generator.initialize(BIKEParameterSpec.bike128, secureRandom);
                break;
            case "BIKE5":
                generator = KeyPairGenerator.getInstance("BIKE", "BCPQC");
                generator.initialize(BIKEParameterSpec.bike256, secureRandom);
                break;
            case "HQC1":
                generator = KeyPairGenerator.getInstance("HQC", "BCPQC");
                generator.initialize(HQCParameterSpec.hqc128, secureRandom);
                break;
            case "HQC5":
                generator = KeyPairGenerator.getInstance("HQC", "BCPQC");
                generator.initialize(HQCParameterSpec.hqc256, secureRandom);
                break;
            default:
                System.err.println("FOUND NONE MATCHING");
                return null;
        }
        return generator.generateKeyPair();
    }

    /**
     * Method which returns the XML identifier of the signature algorithm based on the publicKey.getAlgorithm() result.
     * @param publicKey
     * @return
     */
    public static String getXMLSigAlgName(PublicKey publicKey)
    {
        String algName = publicKey.getAlgorithm();
        int curveBits = 0;
        if (publicKey instanceof ECPublicKey) {
            curveBits = ((ECPublicKey)publicKey).getQ().getCurve().getFieldSize();
        }

        switch (algName.toUpperCase()){
            case "RSA":
                return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
            case "ECDSA":
                if (curveBits == 521) {
                    return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
                } else {
                    return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
                }
            case "DILITHIUM2":
            case "DILITHIUM5":
                return "http://www.w3.org/2023/02/xmldsig-pqc#dilithium";
            case "FALCON-512":
            case "FALCON-1024":
                return "http://www.w3.org/2023/02/xmldsig-pqc#falcon";
            case "SPHINCS+-SHA2-128S":
            case "SPHINCS+-SHA2-256S":
                return "http://www.w3.org/2023/02/xmldsig-pqc#sphincsplus";
            case "MLDSA44ANDECDSAP256":
                return "http://www.w3.org/2023/02/xmldsig-pqc-composites#mldsa44andecdsap256";
            case "MLDSA87ANDECDSAP384":
                return "http://www.w3.org/2023/02/xmldsig-pqc-composites#mldsa87andecdsap384";
            case "MLDSA87ANDECDSAP521":
                return "http://www.w3.org/2023/02/xmldsig-pqc-composites#mldsa87andecdsap521";
            case "FALCON512ANDECDSAP256":
                return "http://www.w3.org/2023/02/xmldsig-pqc-composites#falcon512andecdsap256";
            case "FALCON1024ANDECDSAP521":
                return "http://www.w3.org/2023/02/xmldsig-pqc-composites#falcon1024andecdsap521";
        }
        return null;
    }

    /**
     * Method which returns the XML identifier of the PKE algorithm based on the publicKey.getAlgorithm() result.
     * @param publicKey
     * @return
     */
    public static String getXMLEncAlgName(PublicKey publicKey)
    {
        String algName = publicKey.getAlgorithm();
        switch (algName.toUpperCase())
        {
            case "RSA":
                return "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
            case "KYBER512":
            case "KYBER1024":
                return "http://www.w3.org/2023/02/xmlenc-pqc#kyber";
            case "MCELIECE348864":
            case "MCELIECE6688128":
                return "http://www.w3.org/2023/02/xmlenc-pqc#cmce";
            case "BIKE128":
            case "BIKE256":
                return "http://www.w3.org/2023/02/xmlenc-pqc#bike";
            case "HQC-128":
            case "HQC-256":
                return "http://www.w3.org/2023/02/xmlenc-pqc#hqc";
        }
        return null;
    }

    /**
     * Computation of average and standard deviation of an array of values.
     * @param values
     * @param warmup Do not include the first [warmup] results into the computation.
     * @return
     */
    public static double[] getAverageAndStdev(double[] values, int warmup)
    {
        double[] result = new double[2];
        double total = 0;
        int length = values.length;
        for (int i = warmup; i < length; i++)
        {
            total += values[i];
        }

        result[0] = total / (length - warmup);

        double squaresSum = 0;
        for (int i = warmup; i < length; i++)
        {
            squaresSum += Math.pow(values[i] - result[0], 2);
        }

        result[1] = Math.sqrt(squaresSum / (length - warmup - 1)); //-1 unbiased estimate

        return result;
    }



}
