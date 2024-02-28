package pq.saml.benchmarks;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class BenchmarkSignatures
{
    private static final Logger LOG = LoggerFactory.getLogger(BenchmarkSignatures.class);

    private static FileWriter resultsFile;
    private static FileWriter samplesFile;

    private static Response templateResponse; //template Response used in the benchmark
    private static AuthnRequest templateRequest; //template AuthnRequest used in the benchmark
    private static int repetitions; //number of repetitions in the benchmark
    private static final int warmup = 100; //extra benchmark repetitions which are excluded from the results as JVM does optimizations at the beginning
    private static boolean testingBCHybrids = false; //are we testing backward compatible hybrid PQ SAML?

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, XMLParserException, UnmarshallingException, MarshallingException, CertificateException, java.security.SignatureException, InvalidKeyException
    {
        if (args.length < 3) {
            System.err.println("Not enough arguments.");
            System.exit(0);
        }

        repetitions = Integer.valueOf(args[0]);
        repetitions += warmup; //always add [warmup] amount of extra loops for benchmark consistency due to JVM

        testingBCHybrids = Boolean.valueOf(args[1]);

        if (testingBCHybrids && args.length != 4) {
            System.err.println("Not enough arguments.");
            System.exit(0);
        }

        //Initialize BouncyCastle
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        Util.initOpenSAML(); //Initialize OpenSAML

        //load templates
        InputStream requestStream = BenchmarkSAML.class.getResourceAsStream("/AuthnRequest.xml");
        InputStream responseStream = BenchmarkSAML.class.getResourceAsStream("/Response.xml");

        if (responseStream.available() == 0 || requestStream.available() == 0)
        {
            throw new IOException("Input file does not exist.");
        }

        templateRequest = (AuthnRequest) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), requestStream);
        templateResponse = (Response) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), responseStream);


        LOG.info("Benchmarking in " + (testingBCHybrids ? "BC mode" : "non-BC mode"));

        //prepare results file header
        resultsFile = new FileWriter("SIGbenchmark_" + (testingBCHybrids ? "bchybrid" : "pure") + "_" + repetitions + "_" + System.currentTimeMillis() + ".txt");
        resultsFile.write("Repetitions: " + repetitions + ", wamrup: " + warmup + "\n");
        resultsFile.write("Algorithm; AuthnRequest sig size; AuthnRequest size; Response sig size; Response size; AuthnRequest sign time avg; AuthnRequest sign time stdev; AuthnRequest verify time avg; AuthnRequest verify time stdev; Response sign time avg; Response sign time stdev; Response verify time avg; Response verify time stdev; Total time avg; Total time stdev;\n");

        //prepare samples file
        samplesFile = new FileWriter("samples_SIGbenchmark_" + (testingBCHybrids ? "bchybrid" : "pure") + "_" + repetitions + "_" + System.currentTimeMillis() + ".txt");

        //run benchmark with algorithms specified in args
        String[] firstAlgList = args[2].toString().split("\\s+"); //parse first list of signature algorithms
        LOG.info("First component signatures: " + args[2]);
        if (testingBCHybrids) { //we are in BC hybrid mode, the second list is the PQ signatures
            String[] secondAlgList = args[3].toString().split("\\s+");
            LOG.info("Hybrid second component signatures " + args[3]);
            runBenchmark(firstAlgList, secondAlgList);
        } else {
            runBenchmark(firstAlgList, null);
        }

        resultsFile.close();
        samplesFile.close();
        LOG.info("benchmark finished");

    }

    private static void runBenchmark(String[] firstAlgList, String[] secondAlgList) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, MarshallingException, UnmarshallingException, CertificateException, java.security.SignatureException, InvalidKeyException, InvalidAlgorithmParameterException
    {
        boolean isBCHybrid = (secondAlgList != null);

        ArrayList<String> combinedAlgList = new ArrayList<>(Arrays.asList(firstAlgList));

        if (!isBCHybrid) {
            secondAlgList = new String[]{""}; //placeholder
        } else {
            combinedAlgList.addAll(Arrays.asList(secondAlgList)); //get combined list of all benchmarked signatures
        }

        HashMap<String, KeyPair> generatedKeyPairs = new HashMap<>();
        HashMap<String, X509Certificate> generatedCertificates = new HashMap<>();

        LOG.info("started generating keys");

        for (String alg : combinedAlgList) {
            generatedKeyPairs.put(alg, Util.generateKeyPair(alg));
            generatedCertificates.put(alg, Util.generateCertificate(generatedKeyPairs.get(alg).getPublic(), generatedKeyPairs.get(alg)));
        }

        LOG.info("finished generating keys");

        StringBuilder rawResultsBuilder = new StringBuilder();

        for (String firstAlg : firstAlgList) {
            for (String secondAlg : secondAlgList) {
                LOG.info("benchmarking " + firstAlg + ", " + secondAlg);

                long totalRequestSize = 0;
                long totalRequestSigSize = 0;
                long totalResponseSize = 0;
                long totalResponseSigSize = 0;

                double[] requestSignTimes = new double[repetitions];
                double[] requestVerifyTimes = new double[repetitions];
                double[] responseSignTimes = new double[repetitions];
                double[] responseVerifyTimes = new double[repetitions];
                double[] totalTimes = new double[repetitions];

                for (int i = 0; i < repetitions; i++) {
                    //create SAML messages from template
                    AuthnRequest authnRequest = XMLObjectSupport.cloneXMLObject(templateRequest);
                    Response response = XMLObjectSupport.cloneXMLObject(templateResponse);

                    //create extensions element inside SAML messages for the second signature
                    if (isBCHybrid) {
                        authnRequest.setExtensions(Util.buildSAMLObject(Extensions.class));
                        response.setExtensions(Util.buildSAMLObject(Extensions.class));
                    }

                    //collect signing certs + keypairs
                    KeyPair[] keyPairs = new KeyPair[2];
                    X509Certificate[] certificates = new X509Certificate[2];
                    keyPairs[0] = generatedKeyPairs.get(firstAlg);
                    certificates[0] = generatedCertificates.get(firstAlg);
                    if (isBCHybrid)
                    {
                        keyPairs[1] = generatedKeyPairs.get(secondAlg);
                        certificates[1] = generatedCertificates.get(secondAlg);
                    }


                    Long start = System.nanoTime(); //request signing time start
                    Util.signSAMLMessage(authnRequest, isBCHybrid, keyPairs, certificates);
                    requestSignTimes[i] = Math.round((System.nanoTime() - start)/100d)/10000d; //request signing time end

                    start = System.nanoTime(); //request verify time start
                    Util.verifyMessageSignature(authnRequest, isBCHybrid);

                    //simulate verification of certificate signatures
                    certificates[0].verify(certificates[0].getPublicKey());
                    if (isBCHybrid) {
                        certificates[1].verify(certificates[1].getPublicKey());
                    }
                    requestVerifyTimes[i] = Math.round((System.nanoTime() - start)/100d)/10000d; //request verify time end

                    start = System.nanoTime(); //response signing time start
                    Util.signSAMLMessage(response, isBCHybrid, keyPairs, certificates);
                    responseSignTimes[i] = Math.round((System.nanoTime() - start)/100d)/10000d; //response signing time end

                    start = System.nanoTime(); //response verify time start
                    Util.verifyMessageSignature(response, isBCHybrid);

                    certificates[0].verify(certificates[0].getPublicKey());
                    if (isBCHybrid) {
                        certificates[1].verify(certificates[1].getPublicKey());
                    }
                    responseVerifyTimes[i] = Math.round((System.nanoTime() - start)/100d)/10000d; //response verify time end

                    //totalTimes[i] = requestSignTimes[i] + responseSignTimes[i] + requestVerifyTimes[i] + responseVerifyTimes[i];
                    //Add all times together
                    totalTimes[i] = Math.round((requestSignTimes[i] + responseSignTimes[i] + requestVerifyTimes[i] + responseVerifyTimes[i])*10000d)/10000d;

                    //Get SAML messages sizes
                    String authnRequestString = Util.getSAMLObjectString(authnRequest);
                    String responseString = Util.getSAMLObjectString(response);

                    totalRequestSize += authnRequestString.length();
                    totalResponseSize += responseString.length();
                    totalRequestSigSize += Util.getSAMLObjectString(authnRequest.getSignature()).length();
                    totalResponseSigSize += Util.getSAMLObjectString(response.getSignature()).length();
                    if (isBCHybrid) {
                        totalRequestSigSize += Util.getSAMLObjectString(authnRequest.getExtensions().getUnknownXMLObjects().get(0)).length();
                        totalResponseSigSize += Util.getSAMLObjectString(response.getExtensions().getUnknownXMLObjects().get(0)).length();
                    }

                    //For every algorithm, save a sample of the messages into file
                    if (i == 0) {
                        samplesFile.write(firstAlg + "+" + secondAlg + "\n");
                        samplesFile.write(authnRequestString + "\n");
                        samplesFile.write(responseString + "\n\n");
                        samplesFile.flush();
                    }
                }

                //process measured times
                double[] requestSignTimeAverageAndStdev = Util.getAverageAndStdev(requestSignTimes, warmup);
                double[] requestVerifyTimeAverageAndStdev = Util.getAverageAndStdev(requestVerifyTimes, warmup);
                double[] responseSignTimeAverageAndStdev = Util.getAverageAndStdev(responseSignTimes, warmup);
                double[] responseVerifyTimeAverageAndStdev = Util.getAverageAndStdev(responseVerifyTimes, warmup);
                double[] totalTimeAverageAndStdev = Util.getAverageAndStdev(totalTimes, warmup);

                //write aggregated results into file
                String output = String.format("%s + %s; %d; %d; %d; %d; %.4f; %.4f; %.4f; %.4f; %.4f; %.4f; %.4f; %.4f; %.4f; %.4f;\n", firstAlg, secondAlg, totalRequestSigSize/repetitions, totalRequestSize/repetitions, totalResponseSigSize/repetitions, totalResponseSize/repetitions, requestSignTimeAverageAndStdev[0], requestSignTimeAverageAndStdev[1], requestVerifyTimeAverageAndStdev[0], requestVerifyTimeAverageAndStdev[1], responseSignTimeAverageAndStdev[0], responseSignTimeAverageAndStdev[1], responseVerifyTimeAverageAndStdev[0], responseVerifyTimeAverageAndStdev[1], totalTimeAverageAndStdev[0], totalTimeAverageAndStdev[1]);
                resultsFile.write(output);
                resultsFile.flush();

                //write raw data into the results file
                StringBuilder totalTimesString = new StringBuilder();
                StringBuilder requestSignTimesString = new StringBuilder();
                StringBuilder requestVerifyTimesString = new StringBuilder();
                StringBuilder responseSignTimesString = new StringBuilder();
                StringBuilder responseVerifyTimesString = new StringBuilder();

                for (int i = warmup; i < repetitions; i++) { //ignore first 100
                    requestSignTimesString.append(requestSignTimes[i] + "; ");
                    requestVerifyTimesString.append(requestVerifyTimes[i] + "; ");
                    responseSignTimesString.append(responseSignTimes[i] + "; ");
                    responseVerifyTimesString.append(responseVerifyTimes[i] + "; ");
                    totalTimesString.append(totalTimes[i] + "; ");
                }

                rawResultsBuilder.append(requestSignTimesString + "\n");
                rawResultsBuilder.append(requestVerifyTimesString + "\n");
                rawResultsBuilder.append(responseSignTimesString + "\n");
                rawResultsBuilder.append(responseVerifyTimesString + "\n");
                rawResultsBuilder.append(totalTimesString + "\n");
                rawResultsBuilder.append("\n");

            }
        }
        resultsFile.write(rawResultsBuilder.toString());


    }




}
