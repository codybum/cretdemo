
import com.google.gson.Gson;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import javax.net.ssl.*;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class CertificateManager {

    private Gson gson;

    private KeyStore keyStore;
    private KeyStore trustStore;
    private char[] keyStorePassword;
    private char[] trustStorePassword;

    private String keyStoreAlias;
    private X509Certificate signingCertificate;
    private PrivateKey signingKey;
    private int YEARS_VALID = 2;
    private X509Certificate[] chain;

    private Path keyStorePath;
    private Path trustStorePath;


    private int keySize = 2048;

    public CertificateManager() {

        try {

            gson = new Gson();

            Path certPath = Paths.get("certs");
            keyStorePath = Paths.get(certPath + "/keyStore.pfx");
            trustStorePath = Paths.get(certPath + "/trustStore.pfx");

            if(!certPath.toFile().exists()) {
                certPath.toFile().mkdir();
            } else {
                if(!certPath.toFile().isDirectory()) {
                    System.out.println("BAD CERT PATH");
                    System.exit(0);
                }
            }

            keySize = 2048;

            this.keyStoreAlias = "region-agent";

            //keyStoreAlias = UUID.randomUUID().toString();
            //keyStorePassword = UUID.randomUUID().toString().toCharArray();

            keyStorePassword = "password".toCharArray();
            trustStorePassword = keyStorePassword;

            keyStore = KeyStore.getInstance("pkcs12");
            trustStore = KeyStore.getInstance("pkcs12");


            keyStore.load(null, null);
            trustStore.load(null, null);

            generateAgentChain();

            //trust self
            addCertificatesToTrustStore(keyStoreAlias, getPublicCertificate());



/*
            if(keyStorePath.toFile().exists() && trustStorePath.toFile().exists()) {
                keyStore.load(new FileInputStream(keyStorePath.toFile()),keyStorePassword);
                trustStore.load(new FileInputStream(trustStorePath.toFile()),trustStorePassword);
            } else {

                keyStore.load(null, null);
                trustStore.load(null, null);

                generateCertChain();

                //trust self
                addCertificatesToTrustStore(keyStoreAlias, getPublicCertificate());

                keyStore.store(new FileOutputStream(keyStorePath.toFile()),keyStorePassword);
                keyStore.store(new FileOutputStream(trustStorePath.toFile()),trustStorePassword);

            }
*/

        } catch(Exception ex) {
            System.out.println("CertificateChainGeneration() Error: " + ex.getMessage());
        }

    }

    public void addCertificatesToTrustStore(String alias, Certificate[] certs) {
        try {
            for(Certificate cert:certs){
                //System.out.println(cert.toString());
                //PublicKey publicKey = cert.getPublicKey();
                //String publicKeyString = Base64.encodeBase64String(publicKey.getEncoded());
                //trustStore.setCertificateEntry(UUID.randomUUID().toString(),cert);
                //.keyStore.setCertificateEntry(alias,cert);
                trustStore.setCertificateEntry(alias,cert);
                //System.out.println(publicKeyString);
            }
        } catch (Exception ex) {
            System.out.println("addCertificatesToTrustStore() : error " + ex.getMessage());
        }
    }

    public X509Certificate[] getPublicCertificate() {
        //X509Certificate[] certs = new X509Certificate[1];
        //certs[0] = chain[0];
        return chain;
        //return certs;
    }

    public X509Certificate[] getCertificate(String alias) {
        X509Certificate[] certChain = null;
        try {
            //Generate leaf certificate
            CertAndKeyGen keyGen2=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen2.generate(keySize);
            PrivateKey topPrivateKey=keyGen2.getPrivateKey();
            X509Certificate topCertificate = keyGen2.getSelfCertificate(new X500Name("CN=TOP"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            Certificate cert = createSignedCertificate(topCertificate,signingCertificate,signingKey);
            //keyStore.setCertificateEntry(alias,cert);
            //trustStore.setCertificateEntry(alias,cert);



            certChain = chain.clone();
            certChain[0] = (X509Certificate)cert;

            storeKeyAndCertificateChain(alias, keyStorePassword, topPrivateKey, certChain);


        } catch(Exception ex) {
            System.out.println("getCertificate : error " + ex.getMessage());
        }

        return  certChain;
    }

    private void generateRegionChain() {
        try{

            /*
            CN: CommonName
            OU: OrganizationalUnit
            O: Organization
            L: Locality
            S: StateOrProvinceName
            C: CountryName
            */

            //Generate ROOT certificate
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen.generate(keySize);
            PrivateKey rootPrivateKey=keyGen.getPrivateKey();

            //X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            //X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT, OU=myTeam, O=MyOrg, L=Lexington, ST=KY, C=US"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=region-3424, OU=region_id"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);

            String privateKeyContent = keyToString(rootPrivateKey);
            String publicKeyContent = certToString(rootCertificate);

            //System.out.println("PRIVATE: [" + privateKeyContent + "]");
            //System.out.println("PUBLIC: [" + publicKeyContent + "]");

            rootPrivateKey = stringToKey(privateKeyContent);
            rootCertificate = stringToCert(publicKeyContent);


            Signature rsas = Signature.getInstance("SHA256WithRSA");
            rsas.initSign(rootPrivateKey);
            rsas.update("TEST MESSAGE".getBytes());

            byte[] realSig = rsas.sign();

            Signature rsav = Signature.getInstance("SHA256WithRSA");
            rsav.initVerify(rootCertificate);
            rsav.update("TEST MESSAGE".getBytes());

            boolean verifies = rsav.verify(realSig);

            System.out.println("signature verifies: " + verifies);

            //Generate intermediate certificate
            CertAndKeyGen keyGen1=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen1.generate(keySize);
            PrivateKey middlePrivateKey=keyGen1.getPrivateKey();

            //X509Certificate middleCertificate = keyGen1.getSelfCertificate(new X500Name("CN=MIDDLE, OU=myTeam, O=MyOrg, L=Lexington, ST=KY, C=US"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            X509Certificate middleCertificate_pre = keyGen1.getSelfCertificate(new X500Name("CN=agent-000, OU=agent_id"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);

            //Generate leaf certificate
            CertAndKeyGen keyGen2=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen2.generate(keySize);
            PrivateKey topPrivateKey=keyGen2.getPrivateKey();

            //X509Certificate topCertificate = keyGen2.getSelfCertificate(new X500Name("CN=TOP, OU=myTeam, O=MyOrg, L=Lexington, ST=KY, C=US"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            X509Certificate topCertificate = keyGen2.getSelfCertificate(new X500Name("CN=plugin-000, OU=plugin_id"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);

            X509Certificate[] certificates = new X509Certificate[2];
            certificates[0] = middleCertificate_pre;
            certificates[1] = rootCertificate;

            addCertificatesToTrustStore("whut", certificates);


            rootCertificate   = createSignedCertificate(rootCertificate,rootCertificate,rootPrivateKey);
            X509Certificate middleCertificate = createSignedCertificate(middleCertificate_pre,rootCertificate,rootPrivateKey);
            topCertificate    = createSignedCertificate(topCertificate,middleCertificate_pre,middlePrivateKey);


            chain = new X509Certificate[3];
            chain[0]=topCertificate;
            chain[1]=middleCertificate;
            chain[2]=rootCertificate;

            //Store the certificate chain
            storeKeyAndCertificateChain(keyStoreAlias, keyStorePassword, topPrivateKey, chain);

            signingCertificate = middleCertificate;
            signingKey = middlePrivateKey;

            //check cert
            addCertificatesToTrustStore(keyStoreAlias, chain);

            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(middleCertificate);

            CertPathParameters certPathParameters = new PKIXBuilderParameters(trustStore, certSelector);
            CertPathBuilderResult certPathBuilderResult = certPathBuilder.build(certPathParameters);
            CertPath certPath = certPathBuilderResult.getCertPath();

            final CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            final PKIXParameters validationParameters = new PKIXParameters(trustStore);
            validationParameters.setRevocationEnabled(true); // if you want to check CRL
            final X509CertSelector keyUsageSelector = new X509CertSelector();
            keyUsageSelector.setKeyUsage(new boolean[] { true, false, true }); // to check digitalSignature and keyEncipherment bits
            validationParameters.setTargetCertConstraints(keyUsageSelector);
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, validationParameters);

            System.out.println(result);

            System.exit(0);


        }catch(Exception ex){
            ex.printStackTrace();
        }
    }

    private void generateAgentChain() {
        try{

            /*
            CN: CommonName
            OU: OrganizationalUnit
            O: Organization
            L: Locality
            S: StateOrProvinceName
            C: CountryName
            */

            String agent_id = "agent-000";
            String plugin_id = "plugin-000";

            String agentCN = "CN=" + agent_id;
            String pluginCNOU = "CN=" + agent_id + ", OU=" + plugin_id;

            //Generate ROOT certificate
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen.generate(keySize);
            PrivateKey rootPrivateKey=keyGen.getPrivateKey();

            //X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            //X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT, OU=myTeam, O=MyOrg, L=Lexington, ST=KY, C=US"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name(agentCN), (long) (365 * 24 * 60 * 60) * YEARS_VALID);

            String privateKeyContent = keyToString(rootPrivateKey);
            String publicKeyContent = certToString(rootCertificate);

            //System.out.println("PRIVATE: [" + privateKeyContent + "]");
            //System.out.println("PUBLIC: [" + publicKeyContent + "]");

            rootPrivateKey = stringToKey(privateKeyContent);
            rootCertificate = stringToCert(publicKeyContent);


            Signature rsas = Signature.getInstance("SHA256WithRSA");
            rsas.initSign(rootPrivateKey);
            rsas.update("TEST MESSAGE".getBytes());

            byte[] realSig = rsas.sign();

            String sig = Base64.getEncoder().encodeToString(realSig);

            System.out.println("SIG [" + sig + "]");

            Signature rsav = Signature.getInstance("SHA256WithRSA");
            rsav.initVerify(rootCertificate);
            rsav.update("TEST MESSAGE".getBytes());

            byte[] decorVal = Base64.getDecoder().decode(sig);

            boolean verifies = rsav.verify(decorVal);

            System.out.println("signature verifies: " + verifies);

            //Generate intermediate certificate
            CertAndKeyGen keyGen1=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen1.generate(keySize);
            PrivateKey middlePrivateKey=keyGen1.getPrivateKey();

            //X509Certificate middleCertificate = keyGen1.getSelfCertificate(new X500Name("CN=MIDDLE, OU=myTeam, O=MyOrg, L=Lexington, ST=KY, C=US"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            X509Certificate middleCertificate_pre = keyGen1.getSelfCertificate(new X500Name(pluginCNOU), (long) (365 * 24 * 60 * 60) * YEARS_VALID);

            rootCertificate   = createSignedCertificate(rootCertificate,rootCertificate,rootPrivateKey);
            X509Certificate middleCertificate = createSignedCertificate(middleCertificate_pre,rootCertificate,rootPrivateKey);


            trustStore.setCertificateEntry("root",rootCertificate);
            trustStore.setCertificateEntry("middle",middleCertificate);

            chain = new X509Certificate[2];
            chain[0]=middleCertificate;
            chain[1]=rootCertificate;

            //Store the certificate chain
            storeKeyAndCertificateChain(keyStoreAlias, keyStorePassword, middlePrivateKey, chain);

            signingCertificate = middleCertificate;
            signingKey = middlePrivateKey;

            //check cert
            //addCertificatesToTrustStore(keyStoreAlias, chain);

            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(middleCertificate);

            CertPathParameters certPathParameters = new PKIXBuilderParameters(trustStore, certSelector);
            CertPathBuilderResult certPathBuilderResult = certPathBuilder.build(certPathParameters);
            CertPath certPath = certPathBuilderResult.getCertPath();

            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            PKIXParameters validationParameters = new PKIXParameters(trustStore);
            validationParameters.setRevocationEnabled(true); // if you want to check CRL
            validationParameters.setAnyPolicyInhibited(true);
            validationParameters.setExplicitPolicyRequired(true);
            validationParameters.setPolicyMappingInhibited(true);
            X509CertSelector keyUsageSelector = new X509CertSelector();
            keyUsageSelector.setKeyUsage(new boolean[] { true, false, true }); // to check digitalSignature and keyEncipherment bits
            validationParameters.setTargetCertConstraints(keyUsageSelector);
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, validationParameters);

            System.out.println(result);


            TrustAnchor anc = result.getTrustAnchor();
            X509Certificate xc = anc.getTrustedCert();
            System.out.println("Subject DN: " + xc.getSubjectDN());
            System.out.println("Issuer DN: " + xc.getIssuerDN());

            System.exit(0);


        }catch(Exception ex){
            ex.printStackTrace();
        }
    }


    private void generatePluginChain() {
        try{

            /*
            CN: CommonName
            OU: OrganizationalUnit
            O: Organization
            L: Locality
            S: StateOrProvinceName
            C: CountryName
            */

            //Generate ROOT certificate
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen.generate(keySize);
            PrivateKey rootPrivateKey=keyGen.getPrivateKey();

            //X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            //X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT, OU=myTeam, O=MyOrg, L=Lexington, ST=KY, C=US"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);
            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=agent-3424, OU=agent_id"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);

            String privateKeyContent = keyToString(rootPrivateKey);
            String publicKeyContent = certToString(rootCertificate);

            //System.out.println("PRIVATE: [" + privateKeyContent + "]");
            //System.out.println("PUBLIC: [" + publicKeyContent + "]");

            rootPrivateKey = stringToKey(privateKeyContent);
            rootCertificate = stringToCert(publicKeyContent);



            //rootCertificate = gson.fromJson(rootCertString,X509Certificate.class);

            //Generate intermediate certificate
            CertAndKeyGen keyGen1=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen1.generate(keySize);
            PrivateKey middlePrivateKey=keyGen1.getPrivateKey();

            X509Certificate middleCertificate = keyGen1.getSelfCertificate(new X500Name("CN=MIDDLE, OU=myTeam, O=MyOrg, L=Lexington, ST=KY, C=US"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);

            //Generate leaf certificate
            CertAndKeyGen keyGen2=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen2.generate(keySize);
            PrivateKey topPrivateKey=keyGen2.getPrivateKey();

            X509Certificate topCertificate = keyGen2.getSelfCertificate(new X500Name("CN=TOP, OU=myTeam, O=MyOrg, L=Lexington, ST=KY, C=US"), (long) (365 * 24 * 60 * 60) * YEARS_VALID);


            rootCertificate   = createSignedCertificate(rootCertificate,rootCertificate,rootPrivateKey);
            middleCertificate = createSignedCertificate(middleCertificate,rootCertificate,rootPrivateKey);
            //topCertificate    = createSignedCertificate(topCertificate,middleCertificate,middlePrivateKey);

            chain = new X509Certificate[2];
            //chain[0]=topCertificate;
            chain[0]=middleCertificate;
            chain[1]=rootCertificate;

            //String alias = "mykey";
            //String keystore = "testkeys.jks";

            //Store the certificate chain
            storeKeyAndCertificateChain(keyStoreAlias, keyStorePassword, topPrivateKey, chain);

            //Reload the keystore and display key and certificate chain info
            //loadCertChain(alias, keyStorePassword, keystore);
            //Clear the keystore
            //clearKeyStore(alias, password, keystore);
            signingCertificate = middleCertificate;
            signingKey = middlePrivateKey;

        }catch(Exception ex){
            ex.printStackTrace();
        }
    }


    public TrustManager[] getTrustManagers() {
        TrustManager[] trustManagers = null;
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            trustManagers = trustManagerFactory.getTrustManagers();

        } catch(Exception ex) {
            System.out.println("getTrustManagers Error : " + ex.getMessage());
        }
        return trustManagers;
    }

    public KeyManager[] getKeyManagers() {
        KeyManager[] keyManagers = null;
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyStorePassword);
            keyManagers = keyManagerFactory.getKeyManagers();

        } catch(Exception ex) {
            System.out.println("getKeyManagers Error : " + ex.getMessage());
        }
        return keyManagers;
    }

    private void storeKeyAndCertificateChain(String alias, char[] password, Key key, X509Certificate[] chain) throws Exception{


        //KeyStore keyStore=KeyStore.getInstance("jks");
        //keyStore=KeyStore.getInstance("jks");
        //keyStore.load(null,null);

        keyStore.setKeyEntry(alias, key, password, chain);

        //trustStore.setKeyEntry(alias, key, password, chain);

        //trustStore = keyStore;
        //TODO trying to to save
        //keyStore.store(new FileOutputStream(keystore),password);


    }

    private X509Certificate createSignedCertificate(X509Certificate cetrificate,X509Certificate issuerCertificate,PrivateKey issuerPrivateKey){
        try{
            Principal issuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();

            byte[] inCertBytes = cetrificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);

            //various versions of java work diff
            try{
                //info.set( X509CertInfo.SUBJECT, new CertificateSubjectName( owner ) );
                info.set( X509CertInfo.ISSUER, new CertificateIssuerName( (X500Name) issuer ) );
            } catch(Exception e){
                //info.set( X509CertInfo.SUBJECT, owner );
                info.set( X509CertInfo.ISSUER, issuer );
            }


            //info.set(X509CertInfo.ISSUER, new CertificateIssuerName((X500Name) issuer));

            //No need to add the BasicContraint for leaf cert

            if(!cetrificate.getSubjectDN().getName().equals("CN=TOP")){
                CertificateExtensions exts=new CertificateExtensions();
                BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
                exts.set(BasicConstraintsExtension.NAME,new BasicConstraintsExtension(false, bce.getExtensionValue()));
                info.set(X509CertInfo.EXTENSIONS, exts);
            }


            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);

            return outCert;
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return null;
    }

    private String getStringFromCert(X509Certificate cert) {
        String certString = null;
        try {
            certString = Base64.getEncoder().encodeToString(cert.getEncoded());

        } catch(Exception ex) {
            System.out.println("getStringFromCert() : error " + ex.getMessage());
        }
        return certString;
    }

    private X509Certificate getCertfromString(String certString) {
        X509Certificate cert= null;
        try {
            /*
            byte[] valueDecoded = Base64.decodeBase64(bytesEncoded);
System.out.println("Decoded value is " + new String(valueDecoded));
             */
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            InputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(certString));
            cert = (X509Certificate)certificateFactory.generateCertificate(inputStream);
        } catch(Exception ex) {
            System.out.println("getCertfromString : error " + ex.getMessage());
        }
        return cert;
    }

    public X509Certificate[] getCertsfromJson(String jsonCerts) {
        X509Certificate[] certs = null;
        try {

            Gson gc = new Gson();
            String[] certImportList = gc.fromJson(jsonCerts,String[].class);
            certs = new X509Certificate[3];
            for(int i = 0; i<certImportList.length; i++) {
                certs[i] = getCertfromString(certImportList[i]);
            }

        } catch(Exception ex) {
            System.out.println("getCertsfromJson : error " + ex.getMessage());
            StringWriter sw = new StringWriter();
            ex.printStackTrace(new PrintWriter(sw));
            System.out.println(sw.toString());
        }
        return certs;
    }

    private String[] getStringsFromCerts(X509Certificate[] certs) {
        String[] certStrings = null;
        try {
            certStrings = new String[certs.length];

            for(int i = 0; i < certs.length; i++) {
                certStrings[i] = getStringFromCert(certs[i]);
            }

        } catch(Exception ex) {
            System.out.println("getStringFromCerts() : error " + ex.getMessage());
        }
        return certStrings;
    }

    public String getJsonFromCerts(X509Certificate[] certs) {
        String certJson = null;
        try {
            String[] certArray = getStringsFromCerts(certs);
            Gson gc = new Gson();
            certJson = gc.toJson(certArray);

        } catch(Exception ex) {
            System.out.println("getJsonFromCerts() : error " + ex.getMessage());
        }
        return certJson;
    }

    //unused

    public void updateSSL(X509Certificate[] cert, String alias) {


        try {
            //broker.getSslContext().addTrustManager();

            TrustManager[] trustmanagers = getTrustManagers();
            if (trustmanagers != null) {
                for (TrustManager tm : trustmanagers) {
                    if (tm instanceof X509TrustManager) {
                        //((X509TrustManager) tm).checkClientTrusted(cert, alias);
                        //((X509TrustManager) tm).checkServerTrusted(cert, alias);

                        ((X509TrustManager) tm).checkClientTrusted(cert, "RSA");
                        ((X509TrustManager) tm).checkServerTrusted(cert, "RSA");

                        //((X509TrustManager) tm).checkClientTrusted(null, null);
                        //((X509TrustManager) tm).checkServerTrusted(null, null);

                        //trustmanagers[i] = new TrustManagerDecorator(
                        //        (X509TrustManager) tm, trustStrategy);
                    }
                }
            }

        } catch(Exception ex) {
            System.out.println("updateSSL error " + ex.getMessage());
        }
    }

    public void addCertificatesToKeyStore(String alias, Certificate[] certs) {
        try {
            for(Certificate cert:certs){
                //System.out.println(cert.toString());
                //PublicKey publicKey = cert.getPublicKey();

                //String publicKeyString = Base64.encodeBase64String(publicKey.getEncoded());
                //trustStore.setCertificateEntry(UUID.randomUUID().toString(),cert);
                keyStore.setCertificateEntry(alias,cert);

                //System.out.println(publicKeyString);
            }
        } catch (Exception ex) {
            System.out.println("addCertificatesToTrustStore() : error " + ex.getMessage());
        }
    }

    private void generateCertChain2() {
        try{


            //Generate ROOT certificate
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA256WithRSA",null);
            keyGen.generate(keySize);
            PrivateKey rootPrivateKey=keyGen.getPrivateKey();

            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT-" + keyStoreAlias), (long) (365 * 24 * 60 * 60) * YEARS_VALID);


            rootCertificate   = createSignedCertificate(rootCertificate,rootCertificate,rootPrivateKey);

            chain = new X509Certificate[1];
            chain[0]=rootCertificate;

            //String alias = "mykey";
            //String keystore = "testkeys.jks";

            //Store the certificate chain
            storeKeyAndCertificateChain(keyStoreAlias, keyStorePassword, rootPrivateKey, chain);

            //Reload the keystore and display key and certificate chain info
            //loadCertChain(alias, keyStorePassword, keystore);
            //Clear the keystore
            //clearKeyStore(alias, password, keystore);
            signingCertificate = rootCertificate;
            signingKey = rootPrivateKey;

        }catch(Exception ex){
            ex.printStackTrace();
        }
    }

    public TrustManager getTrustManager() {
        TrustManager trustManager = null;
        try {
            trustManager = getTrustManagers()[0];
            if(trustManager == null) {
                System.out.println("TRUST MANAGER NULL!!!");
            }
        } catch(Exception ex) {
            System.out.println("getTrustManager Error : " + ex.getMessage());
        }
        return trustManager;
    }

    public KeyManager getKeyManager() {
        KeyManager keyManager = null;
        try {
            keyManager = getKeyManagers()[0];
        } catch(Exception ex) {
            System.out.println("getKeyManager Error : " + ex.getMessage());
        }
        return keyManager;
    }

    public Certificate[] getPublicCertificates() {
        Certificate[] certs = null;
        try {
            Key key = keyStore.getKey(keyStoreAlias, keyStorePassword);

            if (key instanceof PrivateKey) {

                certs = keyStore.getCertificateChain(keyStoreAlias);

            }
        } catch(Exception ex) {
            System.out.println("getCertificates() : error " + ex.getMessage());
        }
        return certs;
    }

    public Certificate[] getCertificates() {
        Certificate[] certs = null;
        try {
            Key key = keyStore.getKey(keyStoreAlias, keyStorePassword);

            if (key instanceof PrivateKey) {

                certs = keyStore.getCertificateChain(keyStoreAlias);

            }
        } catch(Exception ex) {
            System.out.println("getCertificates() : error " + ex.getMessage());
        }
        return certs;
    }

    public void loadTrustStoreCertChain(String alias) throws Exception{

        Key key=trustStore.getKey(alias, keyStorePassword);

        if(key instanceof PrivateKey){
            //System.out.println("Get private key : ");
            System.out.println(key.toString());

            Certificate[] certs=trustStore.getCertificateChain(alias);
            System.out.println("Certificate chain length : "+certs.length);
            for(Certificate cert:certs){
                System.out.println(cert.toString());
                PublicKey publicKey = cert.getPublicKey();

                //String publicKeyString = Base64.encodeBase64String(publicKey.getEncoded());
                String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                //trustStore.setCertificateEntry(cert.toString(),cert);
                //keyStore.setCertificateEntry(cert.toString(),cert);

                System.out.println(publicKeyString);
            }
        }else{

            System.out.println("Key is not private key");
            Certificate cert = trustStore.getCertificate(alias);
            if(cert != null) {


                System.out.println(cert.toString());
                PublicKey publicKey = cert.getPublicKey();

                //String publicKeyString = Base64.encodeBase64String(publicKey.getEncoded());
                String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                //trustStore.setCertificateEntry(cert.toString(),cert);
                //keyStore.setCertificateEntry(cert.toString(),cert);

                System.out.println(publicKeyString);
            } else {
                System.out.println("cert null");
            }

        }
    }

    public void loadKeyStoreCertChain(String alias) throws Exception{

        Key key=keyStore.getKey(alias, keyStorePassword);

        if(key instanceof PrivateKey){
            //System.out.println("Get private key : ");
            System.out.println(key.toString());

            Certificate[] certs=keyStore.getCertificateChain(alias);
            System.out.println("Certificate chain length : "+certs.length);
            for(Certificate cert:certs){
                System.out.println(cert.toString());
                PublicKey publicKey = cert.getPublicKey();
                String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                //String publicKeyString = Base64.encodeBase64String(publicKey.getEncoded());
                //trustStore.setCertificateEntry(cert.toString(),cert);
                //keyStore.setCertificateEntry(cert.toString(),cert);

                System.out.println(publicKeyString);
            }
        }else{

            System.out.println("Key is not private key");
            Certificate cert = keyStore.getCertificate(alias);
            if(cert != null) {
                System.out.println(cert.toString());
                PublicKey publicKey = cert.getPublicKey();
                String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                //String publicKeyString = Base64.encodeBase64String(publicKey.getEncoded());
                //trustStore.setCertificateEntry(cert.toString(),cert);
                //keyStore.setCertificateEntry(cert.toString(),cert);

                System.out.println(publicKeyString);
            } else {
                System.out.println("cert null");
            }

        }
    }

    private void loadAndDisplayChain(String alias,char[] password, String keystore) throws Exception{
        //Reload the keystore
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore),password);

        Key key=keyStore.getKey(alias, password);

        if(key instanceof PrivateKey){
            System.out.println("Get private key : ");
            System.out.println(key.toString());

            Certificate[] certs=keyStore.getCertificateChain(alias);
            System.out.println("Certificate chain length : "+certs.length);
            for(Certificate cert:certs){
                System.out.println(cert.toString());
                PublicKey publicKey = cert.getPublicKey();
                String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                //String publicKeyString = Base64.encodeBase64String(publicKey.getEncoded());
                trustStore.setCertificateEntry(cert.toString(),cert);
                System.out.println(publicKeyString);
            }
        }else{
            System.out.println("Key is not private key");
        }
    }

    private  void clearKeyStore(String alias,char[] password, String keystore) throws Exception{
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore),password);
        keyStore.deleteEntry(alias);
        keyStore.store(new FileOutputStream(keystore),password);
    }


    public PrivateKey stringToKey(String certString) {
        PrivateKey privateKey = null;
        try {
            certString = certString.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(certString));
            privateKey = kf.generatePrivate(keySpecPKCS8);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return privateKey;
    }

    public X509Certificate stringToCert(String certString) {
        X509Certificate certificate =  null;
        try {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certString.getBytes()));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return certificate;
    }

    public String certToString(X509Certificate cert) {
        StringWriter sw = new StringWriter();
        try {
            sw.write("-----BEGIN PUBLIC KEY-----\n");
            sw.write(DatatypeConverter.printBase64Binary(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
            sw.write("\n-----END PUBLIC KEY-----\n");
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return sw.toString();
    }

    public String keyToString(PrivateKey privateKey) {
        StringWriter sw = new StringWriter();
        try {
            sw.write("-----BEGIN PRIVATE KEY-----\n");
            sw.write(DatatypeConverter.printBase64Binary(privateKey.getEncoded()).replaceAll("(.{64})", "$1\n"));
            sw.write("\n-----END PRIVATE KEY-----\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sw.toString();
    }


}