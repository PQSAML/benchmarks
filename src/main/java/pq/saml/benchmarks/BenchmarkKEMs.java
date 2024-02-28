package pq.saml.benchmarks;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class BenchmarkKEMs
{
    private static final Logger LOG = LoggerFactory.getLogger(BenchmarkKEMs.class);

    private static FileWriter resultsFile;
    private static FileWriter samplesFile;
    private static Response templateResponse; //template Response used in the benchmark
    private static int repetitions; //number of repetitions in the benchmark
    private static final int warmup = 100; //extra benchmark repetitions which are excluded from the results as JVM does optimizations at the beginning
    private static boolean testingHybrids = false; //are we testing hybrid PQ XML PKE?

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, XMLParserException, UnmarshallingException, MarshallingException
    {

        if (args.length < 3) {
            System.err.println("Not enough arguments.");
            System.exit(0);
        }

        repetitions = Integer.valueOf(args[0]);
        repetitions += warmup; //always add [warmup] amount of extra loops for benchmark consistency due to JVM

        testingHybrids = Boolean.valueOf(args[1]);

        if (testingHybrids && args.length != 4) {
            System.err.println("Not enough arguments.");
            System.exit(0);
        }

        //Initialize BouncyCastle
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        Util.initOpenSAML(); //Initialize OpenSAML

        //load template
        InputStream responseStream = BenchmarkKEMs.class.getResourceAsStream("/Response.xml");

        if (responseStream.available() == 0) {
            throw new IOException("Input file does not exist.");
        }

        templateResponse = (Response) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), responseStream);

        int assertionSize = Util.getSAMLObjectString(templateResponse.getAssertions().get(0)).length(); //get plaintext assertion size

        LOG.info("Benchmarking in " + (testingHybrids ? "hybrid mode" : "purely PQ mode"));

        //prepare results file header
        resultsFile = new FileWriter("KEMbenchmark_" + (testingHybrids ? "hybrid" : "pure") + "_" + repetitions + "_" + System.currentTimeMillis() + ".txt");
        resultsFile.write("Repetitions: " + repetitions + "; warmup: " + warmup + "; assertion size: " + assertionSize + ";\n");
        resultsFile.write("Algorithm; EncryptedAssertion size; Response size; Encryption time avg; Encryption time stdev; Decryption time avg; Decryption time stdev; Total time avg; Total time stdev;\n");

        //prepare samples file
        samplesFile = new FileWriter("samples_KEMbenchmark_" + (testingHybrids ? "hybrid" : "pure") + "_" + repetitions + "_" + System.currentTimeMillis() + ".txt");

        //run benchmark with algorithms specified in args
        String[] firstAlgList = args[2].toString().split("\\s+");
        LOG.info("First component PKEs " + args[2]);
        if (testingHybrids) {
            String[] secondAlgList = args[3].toString().split("\\s+");
            LOG.info("Second component PKEs " + args[3]);
            runBenchmark(firstAlgList, secondAlgList);
        } else {
            runBenchmark(firstAlgList, null);
        }

        resultsFile.close();
        samplesFile.close();
        LOG.info("benchmark finished");

    }

    private static void runBenchmark(String[] firstAlgList, String[] secondAlgList) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, MarshallingException, UnmarshallingException
    {
        boolean isHybrid = (secondAlgList != null);

        ArrayList<String> combinedAlgList = new ArrayList<>(Arrays.asList(firstAlgList));

        if (!isHybrid) {
            secondAlgList = new String[]{""}; //get combined list of all benchmarked KEMs/PKEs
        } else {
            combinedAlgList.addAll(Arrays.asList(secondAlgList));
        }

        HashMap<String, KeyPair> generatedKeyPairs = new HashMap<>();
        HashMap<String, X509Certificate> generatedCertificates = new HashMap<>();

        LOG.info("started generating keys");

        //One RSA keypair for signing certificates
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(3072, new SecureRandom());
        KeyPair sigKeyPair = generator.generateKeyPair();

        for (String alg : combinedAlgList) {
            generatedKeyPairs.put(alg, Util.generateKeyPair(alg));
            generatedCertificates.put(alg, Util.generateCertificate(generatedKeyPairs.get(alg).getPublic(), sigKeyPair));
        }

        LOG.info("finished generating keys");

        StringBuilder rawResultsBuilder = new StringBuilder();

        for (String firstAlg : firstAlgList) {
            for (String secondAlg : secondAlgList) {
                LOG.info("benchmarking " + firstAlg + ", " + secondAlg);

                long totalResponseSize = 0;
                long totalEncryptedAssertionSize = 0;

                double[] encryptionTimes = new double[repetitions];
                double[] decryptionTimes = new double[repetitions];
                double[] totalTimes = new double[repetitions];

                for (int i = 0; i < repetitions; i++) {
                    Response response = XMLObjectSupport.cloneXMLObject(templateResponse); //create Response from template

                    //collect encryption keys and certificates
                    KeyPair[] keyPairs = new KeyPair[2];
                    X509Certificate[] certificates = new X509Certificate[2];
                    keyPairs[0] = generatedKeyPairs.get(firstAlg);
                    certificates[0] = generatedCertificates.get(firstAlg);
                    if (isHybrid)
                    {
                        keyPairs[1] = generatedKeyPairs.get(secondAlg);
                        certificates[1] = generatedCertificates.get(secondAlg);
                    }

                    Long start = System.nanoTime(); //encryption time start
                    EncryptedAssertion encryptedAssertion = Util.encryptAssertion(response.getAssertions().get(0), isHybrid, certificates); //encrypt Assertion inside Response
                    encryptionTimes[i] = Math.round((System.nanoTime() - start)/100d)/10000d; //encryption time end

                    //place encrypted assertion inside Response
                    response.getAssertions().clear();
                    response.getEncryptedAssertions().add(encryptedAssertion);

                    start = System.nanoTime(); //decryption time start
                    Assertion decryptedAssertion = Util.decryptAssertion(response.getEncryptedAssertions().get(0), keyPairs);
                    decryptionTimes[i] = Math.round((System.nanoTime() - start)/100d)/10000d; //decryption time end

                    decryptedAssertion.getVersion(); //simulate reading the assertion - test if decryption successful

                    totalTimes[i] = Math.round((encryptionTimes[i] + decryptionTimes[i])*10000d)/10000d; //sum enc time + dec time and round to 4 decimal places.

                    //Get sizes
                    String responseString = Util.getSAMLObjectString(response);

                    totalEncryptedAssertionSize += Util.getSAMLObjectString(response.getEncryptedAssertions().get(0)).length();
                    totalResponseSize += responseString.length();

                    //For every algorithm, save a sample of the messages into file
                    if (i == 0) {
                        samplesFile.write(firstAlg + "+" + secondAlg + "\n");
                        samplesFile.write(responseString + "\n\n");
                        samplesFile.flush();
                    }

                }

                //process measured times
                double[] encryptionTimeAverageAndStdev = Util.getAverageAndStdev(encryptionTimes, warmup);
                double[] decryptionTimeAverageAndStdev = Util.getAverageAndStdev(decryptionTimes, warmup);
                double[] totalTimeAverageAndStdev = Util.getAverageAndStdev(totalTimes, warmup);

                //write aggregated results into file
                String output = String.format("%s + %s; %d; %d; %.4f; %.4f; %.4f; %.4f; %.4f; %.4f;\n", firstAlg, secondAlg, totalEncryptedAssertionSize/repetitions, totalResponseSize/repetitions, encryptionTimeAverageAndStdev[0], encryptionTimeAverageAndStdev[1], decryptionTimeAverageAndStdev[0], decryptionTimeAverageAndStdev[1], totalTimeAverageAndStdev[0], totalTimeAverageAndStdev[1]);
                resultsFile.write(output);
                resultsFile.flush();

                //write raw data into the results file
                StringBuilder totalTimesString = new StringBuilder();
                StringBuilder encryptionTimesString = new StringBuilder();
                StringBuilder decryptionTimesString = new StringBuilder();

                for (int i = warmup; i < repetitions; i++) { //ignore first 100
                    totalTimesString.append(totalTimes[i] + "; ");
                    encryptionTimesString.append(encryptionTimes[i] + "; ");
                    decryptionTimesString.append(decryptionTimes[i] + "; ");
                }

                rawResultsBuilder.append(firstAlg + " + " + secondAlg + "\n");
                rawResultsBuilder.append(encryptionTimesString + "\n");
                rawResultsBuilder.append(decryptionTimesString + "\n");
                rawResultsBuilder.append(totalTimesString + "\n");
                rawResultsBuilder.append("\n");
            }
        }

        resultsFile.write(rawResultsBuilder.toString());
    }







}
