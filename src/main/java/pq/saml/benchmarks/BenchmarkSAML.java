package pq.saml.benchmarks;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.SecurityException;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

public class BenchmarkSAML
{
    private static final Logger LOG = LoggerFactory.getLogger(BenchmarkSAML.class);
    private static FileWriter resultsFile;
    private static FileWriter samplesFile;
    private static Response templateResponse; //template Response used in the benchmark
    private static AuthnRequest templateRequest; //template AuthnRequest used in the benchmark
    private static int repetitions; //number of repetitions in the benchmark
    private static final int warmup = 100; //extra benchmark repetitions which are excluded from the results as JVM does optimizations at the beginning
    private static boolean testingBCHybrids = false; //are we testing backward compatible hybrid PQ SAML?
    private static boolean testingCompositeHybrids = false; //are we testing non-backward compatible hybrid PQ SAML?

    //List of tested algorithms if we are benchmarking purely PQ SAML (non-hybrid)
    //The syntax is (signature algorithm, PKE algorithm)
    private static final String[][] purelyPQCombinations = {
            {"ECDSAP256", "RSA3072"},
            {"RSA3072", "RSA3072"},
            {"DILITHIUM2", "KYBER512"},
            {"DILITHIUM2", "BIKE1"},
            {"DILITHIUM2", "CMCE1"},
            {"FALCON512", "KYBER512"},
            {"FALCON512", "BIKE1"},
            {"FALCON512", "CMCE1"},
            {"SPHINCS128", "KYBER512"},
            {"SPHINCS128", "BIKE1"},
            {"SPHINCS128", "CMCE1"},
    };

    //List of tested algorithms if we are testing backward compatible hybrid PQ SAML
    //The syntax is (classical sig. alg., classical PKE alg., PQ sig. alg., PQ PKE alg.)
    private static final String[][] bcHybridCombinations = {
            {"ECDSAP256", "RSA3072", "DILITHIUM2", "KYBER512"},
            {"ECDSAP256", "RSA3072", "DILITHIUM2", "BIKE1"},
            {"ECDSAP256", "RSA3072", "DILITHIUM2", "CMCE1"},
            {"ECDSAP256", "RSA3072", "FALCON512", "KYBER512"},
            {"ECDSAP256", "RSA3072", "FALCON512", "BIKE1"},
            {"ECDSAP256", "RSA3072", "FALCON512", "CMCE1"},
    };

    //List of tested algorithms if we are testing non-backward compatible hybrid PQ SAML
    //The syntax is (hybrid PQ composite signature, [classical PKE alg.]+[PQ PKE alg.])
    private static final String[][] compositeCombinations = {
            {"MLDSA44andECDSAP256", "RSA3072+KYBER512"},
            {"MLDSA44andECDSAP256", "RSA3072+BIKE1"},
            {"MLDSA44andECDSAP256", "RSA3072+CMCE1"},
            {"Falcon512andECDSAP256", "RSA3072+KYBER512"},
            {"Falcon512andECDSAP256", "RSA3072+BIKE1"},
            {"Falcon512andECDSAP256", "RSA3072+CMCE1"},
    };

    private static String[][] algorithmsToTest = null;

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, XMLParserException, UnmarshallingException, MarshallingException, CertificateException, SecurityException, java.security.SignatureException, InvalidKeyException
    {
        if (args.length != 3)
        {
            System.err.println("4 arguments are needed.");
            System.exit(0);
        }

        //Initialize BouncyCastle
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        Util.initOpenSAML(); //Initialize OpenSAML

        repetitions = Integer.valueOf(args[0]);
        repetitions += warmup; //always add [warmup] amount of extra loops for benchmark consistency due to JVM

        testingBCHybrids = Boolean.valueOf(args[1]);
        testingCompositeHybrids = Boolean.valueOf(args[2]);

        //cannot test BC hybrids and composite hybrids at the same time.
        if (testingBCHybrids && testingCompositeHybrids) {
            System.err.println("Invalid arguments.");
            System.exit(0);
        }

        //load templates
        InputStream requestStream = BenchmarkSAML.class.getResourceAsStream("/AuthnRequest.xml");
        InputStream responseStream = BenchmarkSAML.class.getResourceAsStream("/Response.xml");

        if (responseStream.available() == 0 || requestStream.available() == 0)
        {
            throw new IOException("Input file does not exist.");
        }

        templateRequest = (AuthnRequest) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), requestStream);
        templateResponse = (Response) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), responseStream);

        if (testingCompositeHybrids) {
            algorithmsToTest = compositeCombinations;
        } else if (testingBCHybrids) {
            algorithmsToTest = bcHybridCombinations;
        } else {
            algorithmsToTest = purelyPQCombinations;
        }

        LOG.info("Benchmarking SAML in " + (testingBCHybrids ? "BC hybrid mode" : (testingCompositeHybrids ? "NON-BC hybrid mode" : "purely mode")));

        //prepare results file header
        resultsFile = new FileWriter("SAMLbenchmark_" + (testingBCHybrids ? "hybrid" : (testingCompositeHybrids ? "composite" : "purely")) + "_" + repetitions + "_" + System.currentTimeMillis() + ".txt");
        resultsFile.write("Repetitions: " + repetitions + "; warmup: " + warmup + "\n");
        resultsFile.write("Algorithm; Bandwidth size; SP time avg; SP time stdev; IDP time average; IDP time stdev; Total time avg; Total time stdev;\n");

        //prepare samples file
        samplesFile = new FileWriter("samples_SAMLbenchmark_" + (testingBCHybrids ? "hybrid" : (testingCompositeHybrids ? "composite" : "purely")) + "_" + repetitions + "_" + System.currentTimeMillis() + ".txt");

        //run benchmark
        runBenchmark();

        //close files, end
        resultsFile.close();
        samplesFile.close();
        LOG.info("benchmark finished");

    }

    //helper function to derive ID from algorithm combination for hashmap
    private static String getPairId(String[] algPair) {
        if (algPair.length == 2) {
            return algPair[0] + "$" + algPair[1];
        } else {
            return algPair[0] + "+" + algPair[2] + "$" + algPair[1] + "+" + algPair[3];
        }

    }

    private static void runBenchmark() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, MarshallingException, UnmarshallingException, SecurityException, CertificateException, java.security.SignatureException, InvalidKeyException
    {
        HashMap<String, KeyPair> sigKeyPairs = new HashMap<>();
        HashMap<String, KeyPair> sigExtraKeyPairs = new HashMap<>();
        HashMap<String, KeyPair> kemKeyPairs = new HashMap<>();
        HashMap<String, KeyPair> kemExtraKeyPairs = new HashMap<>();
        HashMap<String, X509Certificate> sigCertificates = new HashMap<>();
        HashMap<String, X509Certificate> sigExtraCertificates = new HashMap<>();
        HashMap<String, X509Certificate> kemCertificates = new HashMap<>();
        HashMap<String, X509Certificate> kemExtraCertificates = new HashMap<>();

        LOG.info("started generating keys");

        for (String[] algPair : algorithmsToTest)
        {

            String algPairId = getPairId(algPair);

            if (testingCompositeHybrids) {
                sigKeyPairs.put(algPairId, Util.generateKeyPair(algPair[0])); //composite keypair

                String[] kemAlgs = algPair[1].split("\\+");
                kemKeyPairs.put(algPairId, Util.generateKeyPair(kemAlgs[0])); //classical PKE keypair
                kemExtraKeyPairs.put(algPairId, Util.generateKeyPair(kemAlgs[1])); //PQ PKE keypair

                sigCertificates.put(algPairId, Util.generateCertificate(sigKeyPairs.get(algPairId).getPublic(), sigKeyPairs.get(algPairId)));

                //we need to decompose the composite keys so we can sign KEM/PKE certificates appropriately: classical PKE with classical signature, PQ PKE with post-quantum signature.
                CompositePrivateKey signingCompositePrivateKey = (CompositePrivateKey) sigKeyPairs.get(algPairId).getPrivate();
                CompositePublicKey signingCompositePublicKey = (CompositePublicKey) sigKeyPairs.get(algPairId).getPublic();
                KeyPair classicalKeyPair = new KeyPair(signingCompositePublicKey.getPublicKeys().get(1), signingCompositePrivateKey.getPrivateKeys().get(1));
                KeyPair pqKeyPair = new KeyPair(signingCompositePublicKey.getPublicKeys().get(0), signingCompositePrivateKey.getPrivateKeys().get(0));

                kemCertificates.put(algPairId, Util.generateCertificate(kemKeyPairs.get(algPairId).getPublic(), classicalKeyPair));
                kemExtraCertificates.put(algPairId, Util.generateCertificate(kemExtraKeyPairs.get(algPairId).getPublic(), pqKeyPair));
            } else {
                sigKeyPairs.put(algPairId, Util.generateKeyPair(algPair[0]));
                kemKeyPairs.put(algPairId, Util.generateKeyPair(algPair[1]));
                sigCertificates.put(algPairId, Util.generateCertificate(sigKeyPairs.get(algPairId).getPublic(), sigKeyPairs.get(algPairId)));
                kemCertificates.put(algPairId, Util.generateCertificate(kemKeyPairs.get(algPairId).getPublic(), sigKeyPairs.get(algPairId)));

                if (testingBCHybrids) //if we are testing BC hybrids, we need to generate the extra signature keypair and extra PKE keypairs (extra ones are PQ)
                {
                    sigExtraKeyPairs.put(algPairId, Util.generateKeyPair(algPair[2]));
                    kemExtraKeyPairs.put(algPairId, Util.generateKeyPair(algPair[3]));
                    sigExtraCertificates.put(algPairId, Util.generateCertificate(sigExtraKeyPairs.get(algPairId).getPublic(), sigExtraKeyPairs.get(algPairId)));
                    kemExtraCertificates.put(algPairId, Util.generateCertificate(kemExtraKeyPairs.get(algPairId).getPublic(), sigExtraKeyPairs.get(algPairId)));
                }
            }
        }

        LOG.info("finished generating keys");

        StringBuilder rawResultsBuilder = new StringBuilder();

        for (String[] algPair : algorithmsToTest) {
            String algPairId = getPairId(algPair);

            LOG.info("started benchmarking " + algPairId);

            long totalBandwidth = 0;
            double[] totalTimes = new double[repetitions]; //array to store total time for each iteration
            double[] spTimes = new double[repetitions]; //array to store SP time for each iteration
            double[] idpTimes = new double[repetitions]; //array to store IdP time for each iteration

            for (int i = 0; i < repetitions; i++) {
                //create SAML messages from template
                AuthnRequest authnRequest = XMLObjectSupport.cloneXMLObject(templateRequest);
                Response response = XMLObjectSupport.cloneXMLObject(templateResponse);

                long start = System.nanoTime(); //SP time (creating AuthnRequest) start

                //adding KEM cert into Extensions
                Extensions extensions = Util.buildSAMLObject(Extensions.class);
                X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
                factory.setEmitEntityCertificate(true);
                X509Credential kemCredential = new BasicX509Credential(kemCertificates.get(algPairId));
                extensions.getUnknownXMLObjects().add(factory.newInstance().generate(kemCredential));

                //add extra kem cert into extensions
                if (testingBCHybrids || testingCompositeHybrids) {
                    X509Credential kemExtraCredential = new BasicX509Credential(kemExtraCertificates.get(algPairId));
                    extensions.getUnknownXMLObjects().add(factory.newInstance().generate(kemExtraCredential));
                }

                authnRequest.setExtensions(extensions);

                //get keypairs to sign the AuthnRequest
                KeyPair[] keyPairsForSign = new KeyPair[2];
                X509Certificate[] certificatesForSign = new X509Certificate[2];
                keyPairsForSign[0] = sigKeyPairs.get(algPairId);
                certificatesForSign[0] = sigCertificates.get(algPairId);

                if (testingBCHybrids) {
                    keyPairsForSign[1] = sigExtraKeyPairs.get(algPairId);
                    certificatesForSign[1] = sigExtraCertificates.get(algPairId);
                }

                Util.signSAMLMessage(authnRequest, testingBCHybrids, keyPairsForSign, certificatesForSign); //sign AuthnRequest

                spTimes[i] = System.nanoTime() - start; //SP time (creating AuthnRequest) end

                start = System.nanoTime(); //IdP time start

                //simulate verification of signature certificates inside AuthnRequest
                certificatesForSign[0].verify(certificatesForSign[0].getPublicKey());
                if (testingBCHybrids) {
                    certificatesForSign[1].verify(certificatesForSign[1].getPublicKey());
                }

                Util.verifyMessageSignature(authnRequest, testingBCHybrids); //Verify signature of AuthnRequest

                //Extract KEM certs from AuthnRequest
                List<XMLObject> certsInExtensions = authnRequest.getExtensions().getUnknownXMLObjects(KeyInfo.DEFAULT_ELEMENT_NAME);
                KeyInfo kemKeyInfoFromRequest = (KeyInfo) certsInExtensions.get(0);
                String certString = kemKeyInfoFromRequest.getX509Datas().get(0).getX509Certificates().get(0).getValue();
                CertificateFactory kemCertFactory = CertificateFactory.getInstance("X.509", "BC");
                X509Certificate kemCertFromRequest = (X509Certificate) kemCertFactory.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(certString)));

                X509Certificate kemExtraCertFromRequest = null;

                //Extract extra KEM cert from AuthnRequest if hybrid
                if (testingBCHybrids || testingCompositeHybrids) {
                    kemKeyInfoFromRequest = (KeyInfo) certsInExtensions.get(1);
                    certString = kemKeyInfoFromRequest.getX509Datas().get(0).getX509Certificates().get(0).getValue();
                    kemExtraCertFromRequest = (X509Certificate) kemCertFactory.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(certString)));
                }

                //Collect encryption certificates
                X509Certificate[] certificatesForEncryption = new X509Certificate[2];
                certificatesForEncryption[0] = kemCertFromRequest;

                //simulate verification of encryption certificates
                PublicKey kemCertVerifyPubKey = sigKeyPairs.get(algPairId).getPublic();
                PublicKey kemExtraCertVerifyPubKey = null;

                if (testingBCHybrids) {
                    kemExtraCertVerifyPubKey = sigExtraKeyPairs.get(algPairId).getPublic();
                }

                if (testingCompositeHybrids) {
                    CompositePublicKey compositePublicKey = (CompositePublicKey)sigKeyPairs.get(algPairId).getPublic();
                    kemCertVerifyPubKey = compositePublicKey.getPublicKeys().get(1);
                    kemExtraCertVerifyPubKey = compositePublicKey.getPublicKeys().get(0);
                }

                certificatesForEncryption[0].verify(kemCertVerifyPubKey);

                if (testingBCHybrids || testingCompositeHybrids) {
                    certificatesForEncryption[1] = kemExtraCertFromRequest;
                    certificatesForEncryption[1].verify(kemExtraCertVerifyPubKey);
                }

                //Encrypt assertion using public keys from extracted certificates
                EncryptedAssertion encryptedAssertion = Util.encryptAssertion(response.getAssertions().get(0), testingBCHybrids || testingCompositeHybrids, certificatesForEncryption);
                response.getAssertions().clear();
                response.getEncryptedAssertions().add(encryptedAssertion);

                Util.signSAMLMessage(response, testingBCHybrids, keyPairsForSign, certificatesForSign); //Sign Response

                idpTimes[i] = Math.round((System.nanoTime() - start)/100d)/10000d; //IdP time end, convert to ms with 4 decimal places

                start = System.nanoTime(); // SP time (processing Response) start

                //simulate verification of signature certificates inside Response
                certificatesForSign[0].verify(certificatesForSign[0].getPublicKey());
                if (testingBCHybrids) {
                    certificatesForSign[1].verify(certificatesForSign[1].getPublicKey());
                }

                Util.verifyMessageSignature(response, testingBCHybrids); //verify Response signature

                //Collect decryption PKE keys
                KeyPair[] keyPairsForDecryption = new KeyPair[2];
                keyPairsForDecryption[0] = kemKeyPairs.get(algPairId);

                if (testingBCHybrids || testingCompositeHybrids) {
                    keyPairsForDecryption[1] = kemExtraKeyPairs.get(algPairId);
                }

                Assertion decryptedAssertion = Util.decryptAssertion(response.getEncryptedAssertions().get(0), keyPairsForDecryption); //Decrypt assertion
                decryptedAssertion.getVersion(); //simulate reading the assertion - test if decryption successful

                spTimes[i] = Math.round((spTimes[i] + (System.nanoTime() - start))/100d)/10000d; //SP time end (combined), convert to ms with 4 decimal places

                totalTimes[i] = Math.round((spTimes[i] + idpTimes[i])*10000d)/10000d; //sum SP time + IdP time and round to 4 decimal places.

                //Get SAML messages sizes
                String authnRequestString = Util.getSAMLObjectString(authnRequest);
                String responseString = Util.getSAMLObjectString(response);
                totalBandwidth += authnRequestString.length();
                totalBandwidth += responseString.length();

                //For every algorithm, save a sample of the messages into file
                if (i == 0) {
                    samplesFile.write(algPairId + "\n");
                    samplesFile.write(authnRequestString + "\n");
                    samplesFile.write(responseString + "\n\n");
                    samplesFile.flush();
                }
            }

            //process measured times
            double[] spTimeAverageAndStdev = Util.getAverageAndStdev(spTimes, warmup);
            double[] idpTimeAverageAndStdev = Util.getAverageAndStdev(idpTimes, warmup);
            double[] totalTimeAverageAndStdev = Util.getAverageAndStdev(totalTimes, warmup);

            //write aggregated results into file
            String output = String.format("%s; %d; %.4f; %.4f; %.4f; %.4f; %.4f; %.4f;\n", algPairId, totalBandwidth/repetitions, spTimeAverageAndStdev[0], spTimeAverageAndStdev[1], idpTimeAverageAndStdev[0], idpTimeAverageAndStdev[1], totalTimeAverageAndStdev[0], totalTimeAverageAndStdev[1]);
            resultsFile.write(output);
            resultsFile.flush();

            //write raw data into the results file
            StringBuilder spTimesString = new StringBuilder();
            StringBuilder idpTimesString = new StringBuilder();
            StringBuilder totalTimesString = new StringBuilder();


            for (int i = warmup; i < repetitions; i++) { //ignore first 100
                spTimesString.append(spTimes[i] + "; ");
                idpTimesString.append(idpTimes[i] + "; ");
                totalTimesString.append(totalTimes[i] + "; ");
            }

            rawResultsBuilder.append(algPairId + "\n");
            rawResultsBuilder.append(spTimesString + "\n");
            rawResultsBuilder.append(idpTimesString + "\n");
            rawResultsBuilder.append(totalTimesString + "\n");
            rawResultsBuilder.append("\n");

        }
        resultsFile.write(rawResultsBuilder.toString());
    }





}
