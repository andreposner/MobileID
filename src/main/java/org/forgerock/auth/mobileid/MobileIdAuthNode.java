/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */


package org.forgerock.auth.mobileid;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.identity.idm.*;
import com.sun.identity.idsvcs.UserDetails;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import javax.net.ssl.SSLContext;
import java.net.Socket;
import java.security.KeyStore;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContexts;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;
import org.apache.http.*;
// import sun.util.resources.LocaleData;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import java.util.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.AUTH_LEVEL;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.auth.node.api.Action.send;
import org.forgerock.openam.core.CoreWrapper;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.*;
import org.forgerock.openam.utils.CollectionUtils;
import javax.inject.Inject;
import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.util.i18n.PreferredLocales;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
// import javax.json.Json;
// import javax.json.JsonArray;
// import javax.json.JsonObject;
// import javax.json.JsonReader;
//import javax.json.JsonValue;


/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
        configClass      = MobileIdAuthNode.Config.class)

public class MobileIdAuthNode extends AbstractDecisionNode {
    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "MobileIdAuthNode";
    private static String userLang = "";
    private static String msisdn = "";
    // private static String language = "";
    private static String userId = "";
    private static String jsonRequest = "";
    private static String jsonResponse = "";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    private String p7subjectSerialNumber;

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default String jsonAddress() {
            return "https://mobileid.swisscom.com/rest/service";
        }

        @Attribute(order = 200)
        default String dtbs() {
            return "Demo: Corporate Login:";
        }

        @Attribute(order = 300)
        default String applicationProviderId() {
            return "mid://dev.swisscom.ch";
        }

        @Attribute(order = 400)
        default String applicationProviderPassword() {
            return "disabled";
        }

        @Attribute(order = 500)
        default String userLoginAttribute() {
            return "uid";
        }

        @Attribute(order = 600)
        default String msisdnAttribute() {
            return "telephoneNumber";
        }

        @Attribute(order = 700)
        default String languageAttribute() {
            return "preferredLanguage";
        }

        @Attribute(order = 800)
        default String trustStoreFile() {
            return "/usr/local/forgerock/openam/openam/my-truststore.p12";
        }

        @Attribute(order = 900)
        default String trustStorePassword() {
            return "changeit";
        }

        @Attribute(order = 1000)
        default String caSslAlias() {
            return "mobileid-ca-ssl";
        }

        @Attribute(order = 1100)
        default String caSignAlias() {
            return "mobileid-ca-sign";
        }

        @Attribute(order = 1200)
        default String keyStoreFile() {
            return "/usr/local/forgerock/openam/openam/my-keystore.p12";
        }

        @Attribute(order = 1300)
        default String keyStorePassword() {
            return "changeit";
        }

        @Attribute(order = 1400)
        default String privateKeyAlias() {
            return "mobileid.forgerock.ch";
        }

        @Attribute(order = 1500)
        default String timeOut() {
            return"80";
        }

        @Attribute(order = 1600)
        default Integer connectionTimeout() {
            return 90;
        }
    }


    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public MobileIdAuthNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    // temp.
    public void debugmessage(String s) {
        System.out.println(s);
    }

    public Integer randomWithBounds(Integer lb, Integer hb) {
        Random r = new Random();
        int low = lb;
        int high = hb;
        int res = r.nextInt(hb - lb ) + lb;

        return res;
    }

    static final String AB = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUNVWXYZ";
    static SecureRandom rnd = new SecureRandom();

    String randomString (int len) {
        StringBuilder sb = new StringBuilder( len);
        for (int i = 0; i < len; i++)
            sb.append(AB.charAt(rnd.nextInt(AB.length())));
        return sb.toString();
    }

    private IdSearchControl getSearchControl(IdSearchOpModifier modifier, Map<String, Set<String>> avMap) {
        IdSearchControl control = new IdSearchControl();
        control.setMaxResults(1);
        control.setSearchModifiers(modifier, avMap);
        return control;
    }

    public String MSSJsonSignatureRequest(String phone, String language) {
        String APPID = config.applicationProviderId();
        String APPPWD = config.applicationProviderPassword();
        // TODO: cleanup
        // AP_INSTANT=$(date +%Y-%m-%dT%H:%M:%S%:z)
        // valid XML DateTime: '2018-10-04T12:50:24.734'"
        // String apInstant = LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME);
        // DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss xxx", Locale.US);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'+00:00'", Locale.US);
        LocalDateTime dt = LocalDateTime.now();
        String apInstant  = formatter.format(dt);
        String APtransId = "AP.Test." + randomWithBounds(10000, 100000) + "." + randomWithBounds(1000, 10000);
        String msisdn = phone;
        String DTBS = config.dtbs();
        // String randomString(int len) {
        //    StringBuilder sb = new StringBuilder( len);
        //    for (int i = 0; i < len; i++)
        //        sb.append(AB.charAt(rnd.nextInt(AB.length())));
        //    return sb.toString();
        //}
        String transId = randomString(6);
        String USERLANG = language;
        String TIMEOUT = config.timeOut();
        String payload = "{\"MSS_SignatureReq\": {" +
                "\"MajorVersion\": \"1\"," +
                "\"MinorVersion\":\"1\"," +
                "\"AP_Info\": {" +
                "\"AP_ID\": \"" + APPID + "\"," +
                "\"AP_PWD\": \"" + APPPWD + "\"," +
                "\"Instant\": \"" + apInstant + "\", " +
                "\"AP_TransID\": \"" + APtransId + "\"" +
                "}," +
                "\"MSSP_Info\": {" +
                "\"MSSP_ID\": {" +
                "\"URI\": \"http://mid.swisscom.ch\"" +
                "} " +
                "}, " +
                "\"MobileUser\": {" +
                "\"MSISDN\": \"" + msisdn + "\"}," +
                "\"MessagingMode\": \"synch\", " +
                "\"DataToBeSigned\": {" +
                "\"MimeType\": \"text/plain\"," +
                "\"Encoding\": \"UTF-8\", " +
                "\"Data\": \"" + DTBS + " (" + transId + ")\"" +
                "}," +
                "\"TimeOut\": \"" + TIMEOUT + "\"," +
                "\"SignatureProfile\": \"http://mid.swisscom.ch/MID/v1/AuthProfile1\", " +
                "\"AdditionalServices\": [" +
                "{ " +
                "\"Description\": \"http://mss.ficom.fi/TS102204/v1.0.0#userLang\", " +
                "\"UserLang\": {" +
                "\"Value\": \"" + USERLANG + "\"" +
                "}" +
                "}" +
                "]" +
                "}" +
                "}";

        return payload;
    }

    public SSLContext initSSLContext () {
        try {
            final KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(config.keyStoreFile()), config.keyStorePassword().toCharArray());
            final KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(new FileInputStream(config.trustStoreFile()), config.trustStorePassword().toCharArray());

            Enumeration<String> aliases = keyStore.aliases();
            String output = "";
            while (aliases.hasMoreElements()) {
                output = output + aliases.nextElement();
            }
            String finalOutput = output;

            final SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(trustStore, null)
                    .loadKeyMaterial(keyStore, config.keyStorePassword().toCharArray(), new PrivateKeyStrategy() {
                        @Override
                        public String chooseAlias(Map<String, PrivateKeyDetails> map, Socket socket) {
                            debugmessage("[" + DEBUG_FILE + "]: Using private key with alias: '" + finalOutput + "'.");
                            return finalOutput;
                        }
                    })
                    .build();
            return sslContext;

        } catch (KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException
                | IOException | KeyManagementException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean validateMSSResponse(String jsonReq, String jsonRes)  {
        String request = jsonReq;
        String response = jsonRes;
        // Request:
        // {
        //    "MSS_SignatureReq": {
        //     "MajorVersion": "1",
        //     "MinorVersion": "1",
        //     "AP_Info": {
        //         "AP_ID": "mid://dev.swisscom.ch",
        //         "AP_PWD": "disabled",
        //         "Instant": "2018-10-04T15:11:59+00:00",
        //         "AP_TransID": "AP.TEST.14489.7540"
        //     },
        //     "MSSP_Info": {
        //         "MSSP_ID": {
        //             "URI": "http://mid.swisscom.ch/"
        //         }
        //     },
        //     "MobileUser": {
        //         "MSISDN": "+41795552343"
        //     },
        //     "MessagingMode": "synch",
        //             "DataToBeSigned": {
        //         "MimeType": "text/plain",
        //                 "Encoding": "UTF-8",
        //                 "Data": "test.com: Do you want to login to corporate VPN? (Ac8KQA)"
        //     },
        //     "TimeOut":"80",
        //             "SignatureProfile": "http://mid.swisscom.ch/MID/v1/AuthProfile1",
        //             "AdditionalServices": [
        //     {
        //         "Description": "http://mss.ficom.fi/TS102204/v1.0.0#userLang",
        //             "UserLang": {
        //         "Value": "en"
        //     }
        //     }
        // ]
        // }
        // }

        // Response
        // {
        // "MSS_SignatureResp":{
        //  "AP_Info":{
        //      "AP_ID":"mid://dev.swisscom.ch",
        //      "AP_TransID":"AP.Test.46754.5951",
        //      "Instant":"2018-10-05T15:37:00.000Z"
        //  },
        // "MSSP_Info":{
        //      "Instant":"2018-10-05T15:37:26.040Z",
        //      "MSSP_ID":{
        //          "URI":"http://mid.swisscom.ch/"
        //        }
        //      },
        //  "MSSP_TransID":"HE5mwps6",
        //  "MSS_Signature":{
        //      "Base64Signature":"MI... AAA=="
        //  },
        //  "MajorVersion":"1",
        //  "MinorVersion":"1",
        //  "MobileUser":{
        //      "MSISDN":"+41795552343
        //  },
        //  "Status":{
        //      "StatusCode":
        //      {
        //          "Value":"500"
        //      },
        //      "StatusMessage":"SIGNATURE"
        //      }
        //  }
        // }
        try {
            ObjectMapper reqOM = new ObjectMapper();
            JsonNode reqRootNode = reqOM.readTree(jsonReq);
            JsonNode reqApTransId = reqRootNode.path("MSS_SignatureReq").path("AP_Info").path("AP_TransID");
            // debugmessage("[" + DEBUG_FILE + "]: AP TransID from Request: '" + reqApTransId.asText() + "'.");
            JsonNode reqMsisdn = reqRootNode.path("MSS_SignatureReq").path("MobileUser").path("MSISDN");
            // debugmessage("[" + DEBUG_FILE + "]: MSISDN from Request: '" + reqMsisdn.asText() + "'.");

            ObjectMapper resOM = new ObjectMapper();
            JsonNode resRootNode = resOM.readTree(jsonRes);
            JsonNode resStatusCode = resRootNode.path("MSS_SignatureResp").path("Status").path("StatusCode").path("Value");
            // debugmessage("[" + DEBUG_FILE + "]: StatusCode from Response: '" + resStatusCode.asText() + "'.");
            JsonNode resApTransId = resRootNode.path("MSS_SignatureResp").path("AP_Info").path("AP_TransID");
            // debugmessage("[" + DEBUG_FILE + "]: AP TransID from Response: '" + resApTransId.asText() + "'.");
            JsonNode resMsisdn = resRootNode.path("MSS_SignatureResp").path("MobileUser").path("MSISDN");
            // debugmessage("[" + DEBUG_FILE + "]: MSISDN from Response: '" + resMsisdn.asText() + "'.");
            // return statusCodeNode.asInt();
            JsonNode resSignature = resRootNode.path("MSS_SignatureResp").path("MSS_Signature").path("Base64Signature");
            p7subjectSerialNumber = getSubjectSerialNosFromP7(resSignature.asText()).get(0);
            debugmessage("[" + DEBUG_FILE + "]: SerialNumber: '" + p7subjectSerialNumber + "'.");

            if (resStatusCode.asInt() == 500) {
                debugmessage("[" + DEBUG_FILE + "]: MSS Status: ok; checking AP_TransID now ...");
                if (reqApTransId.asText().equals(resApTransId.asText())) {
                    debugmessage("[" + DEBUG_FILE + "]: AP Trans ID match (" + resApTransId.asText() + "); checking MSISDN now ...");
                    if (reqMsisdn.asText().equals(resMsisdn.asText())) {
                        debugmessage("[" + DEBUG_FILE + "]: MSISDN match (" + resMsisdn.asText() + ") => will return 'true'");
                        return true;
                    } else {
                        debugmessage("[" + DEBUG_FILE + "]: MSISDN does not match! ( '" + reqMsisdn + "' != '" + resMsisdn + "' => will return 'false'");
                        return false;
                    }
                } else {
                    debugmessage("[" + DEBUG_FILE + "]: AP Trans ID does not match! ( '" + reqApTransId + "' != '" + resApTransId + "' ) => will return 'false'");
                    return false;
                }

            } else {
                debugmessage("[" + DEBUG_FILE + "]: MSS Status: '" + resStatusCode.asText() + "' != 500 => will return 'false'");
                return false;

            }

        } catch (IOException e) {
            debugmessage(
                    "[" + DEBUG_FILE + "]: Could not read MSS JSON : \n" + e.toString());
        }
        return true;
    }

    public boolean verfiyMSSResponse (String jsonResponse ) {
        // TODO: Check whole cert chain
        // TODO: Check Signer Cert against CRL
        // TODO: Check Signer Cert against OCSP
        String json = jsonResponse;
        try {
            ObjectMapper om = new ObjectMapper();
            JsonNode rootNode = om.readTree(json);
            JsonNode signatureNode = rootNode.path("MSS_SignatureResp").path("MSS_Signature").path("Base64Signature");
            byte[] p7DER = java.util.Base64.getDecoder().decode(signatureNode.asText());

            char[] tspw = config.trustStorePassword().toCharArray();

            KeyStore ks = KeyStore.getInstance("PKCS12");
            FileInputStream ksfis = new FileInputStream(config.trustStoreFile());
            BufferedInputStream ksbufin = new BufferedInputStream(ksfis);

            ks.load(ksbufin, tspw);
            java.security.cert.Certificate cert = ks.getCertificate(config.caSignAlias());
            PublicKey pub = cert.getPublicKey();
            // byte[] encodedCert = cert.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    private boolean MobileIdRequest(String phone, String language) {
        String request = "";
        String response = "";
        String userlanguage = language;
        try {
            // initialize
            final SSLContext sslContext = initSSLContext();
            HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).setConnectionTimeToLive(config.connectionTimeout(), TimeUnit.SECONDS).build();

            //POST
            HttpPost jsonRequest = new HttpPost(config.jsonAddress());
            jsonRequest.setHeader("Accept", "application/json");
            jsonRequest.setHeader("Content-Type", "application/json;charset=utf-8");
            String payload = MSSJsonSignatureRequest(msisdn, userlanguage);
            StringEntity entity = new StringEntity(payload);
            jsonRequest.setEntity(entity);
            HttpResponse jsonResponse = httpClient.execute(jsonRequest);

            // Display request headers
            List<Header> httpHeaders = Arrays.asList(jsonRequest.getAllHeaders());
            for (Header header : httpHeaders) {
                debugmessage("[" + DEBUG_FILE + "]: Request-Header: 'name','value': '" + header.getName() + "','" + header.getValue() + "'.");
            }

            // Display request body
            BufferedReader req = new BufferedReader(new InputStreamReader(jsonRequest.getEntity().getContent()));
            String outputReq;
            while ((outputReq = req.readLine()) != null) {
                request = request + outputReq;
            }
            debugmessage("[" + DEBUG_FILE + "]: Request: '" + request + "'.");

            //TODO: remove this
            // Display response body
            BufferedReader res = new BufferedReader(new InputStreamReader(jsonResponse.getEntity().getContent()));
            String outputRes;
            while ((outputRes = res.readLine()) != null) {
                response  = response + outputRes;
            }
            debugmessage("[" + DEBUG_FILE + "]: Response: '" + response + "'.");

            // Display response status code
            int statusCode = jsonResponse.getStatusLine().getStatusCode();
            if (statusCode == 200) {
                debugmessage("[" + DEBUG_FILE + "]: HTTP result code was '200/OK'; will now validate reponse ...");
                if (validateMSSResponse(request, response) == true) {
                    if (verfiyMSSResponse(response) == true) {
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    debugmessage("[" + DEBUG_FILE + "]: Validation of response was not successful => will return 'false' (Despite HTTP result of '200').");
                    return false;
                }
            } else {
                debugmessage("[" + DEBUG_FILE + "]: HTTP Response Code: '" + statusCode + "' != 200 => will retrun 'false'.");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    private ArrayList<String> getSubjectSerialNosFromP7(String b64encodedPKCS7) {
        byte[] p7DER = java.util.Base64.getDecoder().decode(b64encodedPKCS7);
        ArrayList<String> result = new ArrayList<String>();
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(p7DER);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection c = cf.generateCertificates(bis);
            Iterator i = c.iterator();
            while (i.hasNext()) {
                X509Certificate cert = (X509Certificate) i.next();
                String subject = cert.getSubjectDN().getName();
                System.out.println("Subject: " + subject);
                String[] subjectArray = subject.split(",");
                for (int j = 0; j < subjectArray.length; j++) {
                    String entry = subjectArray[j];
                    if (entry.contains("SERIALNUMBER=")) {
                        String serialNo = entry.split("=")[1];
                        System.out.println("New SerialNo: " + serialNo);
                        result.add(serialNo);
                    }
                }
            }
        } catch (Exception e) {

        }
        return result;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        debugmessage("[" + DEBUG_FILE + "]: MobileId started ...");
        debugmessage("[" + DEBUG_FILE + "]: Configuration: MSS baseURL:'" + config.jsonAddress() + "'.");
        debugmessage( "[" + DEBUG_FILE + "]: Configuration: Application Provider Name: '" + config.applicationProviderId() + "'.");
        debugmessage( "[" + DEBUG_FILE + "]: Configuration: DTBS: '" + config.dtbs() + "'.");
        debugmessage( "[" + DEBUG_FILE + "]: Configuration: user login attribute: '" + config.userLoginAttribute() + "'.");
        debugmessage( "[" + DEBUG_FILE + "]: Configuration: msisdn attribute: '" + config.msisdnAttribute() + "'.");
        debugmessage( "[" + DEBUG_FILE + "]: Configuration: language attribute: '" + config.languageAttribute() + "'.");
        debugmessage( "[" + DEBUG_FILE + "]: Configuration: truststore file: '" + config.trustStoreFile() + "'.");
        debugmessage( "[" + DEBUG_FILE + "]: Configuration: keystore file: '" + config.keyStoreFile() + "'.");
        debugmessage( "[" + DEBUG_FILE + "]: Configuration: timeout: '" + config.timeOut() + "'.");

        // msisdn = context.sharedState.get("MSISDN").toString();
        userId = context.sharedState.get("username").toString().replaceAll("\"", "" );
        debugmessage("[" + DEBUG_FILE + "]: Got user: '"+ userId + "'.");

        AMIdentityRepository idrepo = coreWrapper.getAMIdentityRepository(
                coreWrapper.convertRealmPathToRealmDn(context.sharedState.get(REALM).asString()));
        IdSearchResults searchResults;
        final IdSearchControl idsc = new IdSearchControl();

        IdSearchOpModifier mod = IdSearchOpModifier.OR;

        Set<String> avFilterValue = new HashSet<>();
        avFilterValue.add(userId);
        Map<String, Set> avFilter = new HashMap<>();

        avFilter.put(config.userLoginAttribute(), avFilterValue);

        idsc.setTimeOut(0);
        idsc.setAllReturnAttributes(true);
        idsc.setSearchModifiers(mod, avFilter);

        Exception cause = null;
        debugmessage("[" + DEBUG_FILE + "]: User Search: Searching  with BaseDN: '" + coreWrapper.convertRealmPathToRealmDn(context.sharedState.get(REALM).asString()) + "'.");
        debugmessage("[" + DEBUG_FILE + "]: User Search: Searching with Filter: '"+ avFilter + "'.");
        debugmessage("[" + DEBUG_FILE + "]: User Search: Searching with IDS: '"+ idsc.getSearchModifierMap() + "'.");

        try {
             searchResults = idrepo.searchIdentities(IdType.USER, "*", idsc);
             debugmessage("[" + DEBUG_FILE + "]: User Search: Got results: '" + searchResults + "'.");

             Set<AMIdentity> identities = searchResults.getSearchResults();
             debugmessage("[" + DEBUG_FILE + "]: User Search: Found identities: '" + identities + "'.");

             if (identities == null || identities.size() !=1) {
                 debugmessage("[" + DEBUG_FILE + "]: User Search: No user found => access denied!");
                 return  goTo(false).build();
             } else {
                 Iterator it = identities.iterator();

                 // We expect exactly one user to be found
                 AMIdentity user = (AMIdentity) it.next();

                 // Determine MSISDN to use
                 Set<String> msisdnAttrs = user.getAttribute(config.msisdnAttribute());
                 debugmessage("[" + DEBUG_FILE + "]: User Search : Checking found  values for '" + config.msisdnAttribute() + "' = '" + msisdnAttrs  + "' in IdRepo.");
                 if (msisdnAttrs == null || (msisdnAttrs.size() != 1)) {
                     debugmessage("[" + DEBUG_FILE + "]: User Search: Cannot determine useful value for '" + config.msisdnAttribute() + "' => access denied.");
                     return  goTo(false).build();
                 } else {
                     String msisdnAttr = msisdnAttrs.iterator().next();
                     msisdn = msisdnAttr.replaceAll(" ", "" );
                     debugmessage("[" + DEBUG_FILE + "]: User Search: Will use '" + msisdn + "' as value for '" + config.msisdnAttribute() + "'.");
                 }

                 // Determine language to use
                 Set<String> langAttrs = user.getAttribute(config.languageAttribute());
                 debugmessage("[" + DEBUG_FILE + "]: User Search: Checking found values for '" + config.languageAttribute() + "' = '" + langAttrs  + "' in IdRepo.");

                 if (langAttrs == null || (langAttrs.size() != 1)) {
                      debugmessage("[" + DEBUG_FILE + "]: User Search: Cannot determine useful value for '" + config.languageAttribute() + "' => will use 'en'.");
                 } else {
                     String langAttr = langAttrs.iterator().next();
                     if (langAttr!="en" && langAttr!="de" && langAttr!="fr" && langAttr!="it") {
                         debugmessage("[" + DEBUG_FILE + "]: User Search: User's language ('" +  "') not supported => will use 'en'.");
                         userLang = "en";
                     } else {
                         debugmessage("[" + DEBUG_FILE + "]: User Search: Will use '" + userLang + "' as user language.");
                         userLang = langAttr;
                     }
                 }
             }
        } catch (IdRepoException e){
            e.printStackTrace();
        } catch (SSOException e) {
            e.printStackTrace();
        }

        debugmessage("[" + DEBUG_FILE + "]: User Login: Trying MobileId with '" + config.msisdnAttribute() +
                "': '" + msisdn + "' and '" + config.languageAttribute() + "': '" + userLang + "'.");
        if (MobileIdRequest(msisdn, userLang) == true) {
            debugmessage("[" + DEBUG_FILE + "]: MobileId output: 'true'.");
            return goTo(true).build();
        } else {
            debugmessage("[" + DEBUG_FILE + "]: MobileId output: 'false'.");
            return goTo(false).build();
        }
    }
}
