/* ========================================================================
 * Copyright (c) 2011-2012 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

package edu.washington.iam.ws.cabroker.ca.incommon;

import com.google.gson.stream.JsonReader;
import edu.washington.iam.tools.DNSVerifier;
import edu.washington.iam.tools.IamMailMessage;
import edu.washington.iam.tools.IamMailSender;
import edu.washington.iam.tools.WebClient;
import edu.washington.iam.tools.WebClientException;
import edu.washington.iam.tools.XMLHelper;
import edu.washington.iam.ws.cabroker.ca.CertificateAuthority;
import edu.washington.iam.ws.cabroker.exception.CBNotFoundException;
import edu.washington.iam.ws.cabroker.exception.CertificateAuthorityException;
import edu.washington.iam.ws.cabroker.exception.NoPermissionException;
import edu.washington.iam.ws.cabroker.registry.CBCertificate;
import edu.washington.iam.ws.cabroker.registry.CBHistory;
import edu.washington.iam.ws.cabroker.registry.CBRegistry;
import edu.washington.iam.ws.cabroker.util.PEMHelper;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.stream.Collectors;

public class ICCertificateAuthority implements CertificateAuthority {

   private final Logger log =   LoggerFactory.getLogger(getClass());

   private WebClient webClient;
   private CBRegistry cbRegistry;
   private DNSVerifier dnsVerifier;
   private IamMailSender iamMailSender;
   private IamMailMessage certIssuedMessage = null;
   private IamMailMessage certWatcherMessage = null;

   private static String soapUrl = "https://cert-manager.com:443/ws/EPKIManagerSSL";
   private static String soapAction = "";

   private static boolean watchForActivity = false;
   private Thread activityWatcher = null;
   private int refreshInterval = 0;

   //prod strings
   // private static String authDataFile = "/data/local/etc/comodo.pw";
   // private static String orgAndSecretFile = "/data/local/etc/comodo.os";
   //dev strings
   private static String authDataFile = "/Users/jimt/src/UW/IAM/certs/comodo.pw";
   private static String orgAndSecretFile = "/Users/jimt/src/UW/IAM/certs/comodo.os";
   private long authDataModified = 0;
   private long orgAndSecretModified = 0;

   // soap body and parts
   // authdata comes from file at init
   private String authDataTmpl = "<authData>" +
       "<customerLoginUri>LOGINURI</customerLoginUri>" +
       "<login>LOGIN</login>" +
       "<password>PASSWORD</password>" +
       "</authData>";
   private String authData;

   // secret comes from file at init
   private String orgAndSecretTmpl = "<orgId>ORGID</orgId><secretKey>ORGSECRET</secretKey>";
   private String orgAndSecret;

   private static String collectBody = "<tns:collect xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<id>ID</id><formatType>1</formatType></tns:collect>";

   private static String collectPKCS7 = "<tns:collect xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<id>ID</id><formatType>3</formatType></tns:collect>";

   private static String getCollectStatusBody = "<tns:getCollectStatus xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<id>ID</id></tns:getCollectStatus>";

   // SHA-2 types
   private String singleSSLType = "<certType><id>14042</id><name>InCommon SSL (SHA-2)</name>" +
        "<terms>1</terms><terms>1</terms></certType>";
   
   private String multiSSLType = "<certType><id>14044</id><name>InCommon Multi Domain SSL (SHA-2)</name>" +
        "<terms>1</terms><terms>1</terms></certType>";

   private String wildcardSSLType = "<certType><id>14837</id><name>InCommon Wildcard SSL Certificate (SHA-2)</name>" +
        "<terms>1</terms><terms>1</terms></certType>";

/**
   private String singleSSLType = "<certType><id>224</id><name>InCommon SSL (SHA-2)</name>" +
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";
   
   private String multiSSLType = "<certType><id>226</id><name>InCommon Multi Domain SSL (SHA-2)</name>" +
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";

   private String wildcardSSLType = "<certType><id>227</id><name>InCommon Wildcard SSL Certificate (SHA-2)</name>" +
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";
 **/

/** SHA-1 types 
   private String singleSSLType = "<certType><id>62</id><name>InCommon SSL</name>" +
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";

   private String multiSSLType = "<certType><id>64</id><name>InCommon Multi Domain SSL</name>" + 
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";

   private String wildcardSSLType = "<certType><id>63</id><name>InCommon Wildcard SSL Certificate</name>" + 
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";

**/

   private DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
   private DocumentBuilder builder;

   private static Map pemParams = new HashMap<String, String>() {{
      put("format", "x509CO");
   }};
   
   private static Map pkcs7Params = new HashMap<String, String>() {{
      put("format", "base64");
   }};
   
   private Map<String, String> authContentHdrMap;
   private static String enrollBody = "<tns:enroll xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "ORGANDSECRET" +
       "<csr>CSR</csr>" +
       "<phrase>whatsthisfor</phrase>" +
       "ALTNAME" +
       "CERTTYPE" +
       "<numberServers>NUMSERVERS</numberServers>" +
       "<serverType>SERVERTYPE</serverType>" +
       "<term>TERM</term>" +
       "<comments></comments>" +
       "</tns:enroll>";

       // "<subjAltNames xsi:type=\"xsd:string\">ALTNAMES</subjAltNames>" +
   
   private static String renewBody = "<tns:renewById xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<id>RENEWID</id></tns:renewById>";

   public ICCertificateAuthority() throws ParserConfigurationException {
      builder = factory.newDocumentBuilder();
   }


   public int getCertificate(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException {
      log.debug("get cert for " + cert.caId);

      if (cert.renewId!=null && cert.renewId.length()>0 &&
          cert.status!=CBCertificate.CERT_STATUS_DECLINED) return getRenewedCertificate(cert); 

      cert.pemCert = null;
      int status = (-999);
      
      int oldStatus = cert.status;
      if (oldStatus==CBCertificate.CERT_STATUS_REVOKED) return oldStatus;
      refreshSecrets();
    
      try {
         String body = collectBody.replaceFirst("AUTHDATA",authData).replaceFirst("ID", String.valueOf(cert.caId));
         Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element cr = XMLHelper.getElementByName(resp, "collectResponse");
         Element ret = XMLHelper.getElementByName(cr, "return");
         Element sc = XMLHelper.getElementByName(ret, "statusCode");

         status = Integer.parseInt(sc.getTextContent());
         log.debug("status: " + status);
         if ((status==0||status==(-23)) && cert.status!=CBCertificate.CERT_STATUS_RENEWING &&
              cert.status!=CBCertificate.CERT_STATUS_DECLINED) cert.status = CBCertificate.CERT_STATUS_REQUESTED;
         if (status==1 || status==2) cert.status = CBCertificate.CERT_STATUS_ISSUED;
         else if (status==(-21)) cert.status = CBCertificate.CERT_STATUS_REVOKED;
         else if (status==(-40)) throw new CBNotFoundException("not found");
         else if (status<0 && status!=(-23)) throw new CertificateAuthorityException(String.valueOf(status));
    
         if (status==2) {
            Element ssl = XMLHelper.getElementByName(ret, "SSL");
            Element certE = XMLHelper.getElementByName(ssl, "certificate");
            cert.pemCert = certE.getTextContent();
            if (PEMHelper.parseCert(cert) == 0) {
               cert.status = CBCertificate.CERT_STATUS_REQUESTED;  // kind of an assumption, incommon does this when no cert yet
               return 0;
            } 
            Date now = new Date();
            if (cert.expires.before(now)) {
               log.debug("cert available, but is expired");
               status = 0;
               cert.status = CBCertificate.CERT_STATUS_EXPIRED;
            } else {
               Element renew = XMLHelper.getElementByName(ssl, "renewID");
               cert.renewId = renew.getTextContent();
               log.debug("renew: " + cert.renewId);
            }
         }
         if (status==2 && oldStatus!=2) {
            sendNotices(cert);
         }
         cert.updateDB();
         if (status==(-21)) cert.addHistory(CBHistory.CB_HIST_REV, new Date(), "somebody");

      } catch (WebClientException e) {
         throw new CertificateAuthorityException("incommon retrieve:" + e.getMessage());
      }
      return status;
   }

   // the cert has already been gotten.  only update for errors
   public String getCertificatePKCS7(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException {
      log.debug("get plcs7 for " + cert.caId);

      if (cert.renewId!=null && cert.renewId.length()>0) return getRenewedCertificatePKCS7(cert);  // always seems to work

      int status = (-999);
      String pkcs7 = null;
      refreshSecrets();
      try {
         String body = collectPKCS7.replaceFirst("AUTHDATA",authData).replaceFirst("ID", String.valueOf(cert.caId));
         Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element cr = XMLHelper.getElementByName(resp, "collectResponse");
         Element ret = XMLHelper.getElementByName(cr, "return");
         Element sc = XMLHelper.getElementByName(ret, "statusCode");

         status = Integer.parseInt(sc.getTextContent());
         log.debug("status: " + status);
         if (status==0 && cert.status!=CBCertificate.CERT_STATUS_RENEWING) throw new CertificateAuthorityException("certificate is being renewed");
         if (status==(-21)) throw new CertificateAuthorityException("certificate has been revoked");
         if (status==(-40)) throw new CBNotFoundException("certificate is not found");
         if (status<0) throw new CertificateAuthorityException(String.valueOf(status));

         if (status==2) {
            Element ssl = XMLHelper.getElementByName(ret, "SSL");
            Element certE = XMLHelper.getElementByName(ssl, "certificate");
            pkcs7 = certE.getTextContent();
            // log.debug("pkcs7: " + pkcs7);
         }
      } catch (WebClientException e) {
         throw new CertificateAuthorityException("incommon retrieve:" + e.getMessage());
      }

      return pkcs7;
   }


   public int getRenewedCertificate(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException {
      log.debug("get renewed cert for " + cert.caId + " renewId=" + cert.renewId + " status=" + cert.status);
      cert.pemCert = null;
      int status = (-999);
      if (cert.renewId != null && cert.renewId.length() == 0) return status; // shouldn't happen

      int oldStatus = cert.status;
      if (oldStatus == CBCertificate.CERT_STATUS_REVOKED) return oldStatus;
      refreshSecrets();

      try {
         CloseableHttpResponse response = webClient.doRestGet("https://cert-manager.com/api/ssl/v1/collect/" + cert.getCaId(), pemParams, authContentHdrMap);

         if (null == response) throw new CertificateAuthorityException("IO error to CA");

         status = response.getStatusLine().getStatusCode();

         log.debug("status: " + status);

         HttpEntity entity = response.getEntity();

         // Sectigo's REST API generates different statuses/error-codes than the SOAP API;
         // Log and throw an exception based on the error
         if (status > 400) {
            Map<String, String> sectigoReturnMap = parseSectigoError(entity);
            String errorCode = sectigoReturnMap.get("code");
            switch (errorCode) {
               case "-618":  // Discovery is currently running. Please try again later.
               case "-1400": // The request is being processed by Sectigo.
                  cert.status = CBCertificate.CERT_STATUS_RENEWING;
                  break;
               case "-1112": // Certificate can''t be approved cause it has state = ...
                  cert.status = CBCertificate.CERT_STATUS_DECLINED;
                  break;
               case "-5101": // Certificate not found. 
                  cert.status = CBCertificate.CERT_STATUS_GONE;
                  break;
               default:
                  cert.status = CBCertificate.CERT_STATUS_UNKNOWN;
                  log.error("Unhandled Sectigo error: " + errorCode);
                  break;
            }
         }
         else {
            cert.pemCert = new BufferedReader(new InputStreamReader(entity.getContent())).lines().collect(Collectors.joining("\n"));
            response.close();
            if (PEMHelper.parseCert(cert) == 0) {
               cert.status = CBCertificate.CERT_STATUS_RENEWING;  // kind of an assumption, incommon does this when no cert yet
            } else if (status == HttpStatus.SC_OK) {
               cert.status = CBCertificate.CERT_STATUS_ISSUED;
               if (oldStatus != CBCertificate.CERT_STATUS_ISSUED) {
                  sendNotices(cert);
               }
            }
            cert.updateDB();
         }
      } catch (WebClientException | IOException e) {
         throw new CertificateAuthorityException("incommon retrieve:" + e.getMessage());
      }
      return status;
   }

   // the cert has already been gotten.  only update for errors
   public String getRenewedCertificatePKCS7(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException {
      log.debug("get renewed pkcs7 for " + cert.caId + " renewId=" + cert.renewId);
      int status = (-999);
      if (cert.renewId!=null && cert.renewId.length()==0) return ""; // shouldn't happen
      String pkcs7 = null;

      int oldStatus = cert.status;
      refreshSecrets();

      try {
         CloseableHttpResponse response = webClient.doRestGet("https://cert-manager.com/api/ssl/v1/collect/" + cert.getCaId(), pkcs7Params, authContentHdrMap);

         if (null == response) throw new CertificateAuthorityException("IO error to CA");

         status = response.getStatusLine().getStatusCode();

         log.debug("status: " + status);

         HttpEntity entity = response.getEntity();

         // Sectigo's REST API generates different statuses/error-codes than the SOAP API;
         // Log and throw an exception based on the error
         if (status > 400) {
            Map<String, String> sectigoReturnMap = parseSectigoError(entity);
            String errorCode = sectigoReturnMap.get("code");
            switch (errorCode) {
               case "-618":  // Discovery is currently running. Please try again later.
               case "-1400": // The request is being processed by Sectigo.
                  throw new CertificateAuthorityException("renewing: errorCode = " + errorCode);
               case "-5101": // Certificate not found. 
                  throw new CBNotFoundException("not found");
               default:
                  log.error("Unhandled Sectigo error: " + errorCode);
                  throw new CertificateAuthorityException(String.valueOf(status));
            }
         }
         pkcs7 = IOUtils.toString(new InputStreamReader(entity.getContent()));
         response.close();
      } catch (WebClientException | IOException e) {
         throw new CertificateAuthorityException("incommon retrieve:" + e.getMessage());
      }
      return pkcs7;
   }

   private Map<String, String> parseSectigoError(HttpEntity errEntity) throws IOException {
      // parse out Sectigo REST error; see the 'Errors' section of the
      // Certificate Manager 22.10 REST API
      HashMap<String, String> errorMap = new HashMap<>();

      JsonReader reader = new JsonReader(new InputStreamReader(errEntity.getContent()));
      reader.beginObject();
      while (reader.hasNext()) {
         errorMap.put(reader.nextName(), reader.nextString());
      }
      reader.endObject();

      log.error("Error calling Sectigo REST API: " + errorMap.get("description") + "; error code: " + errorMap.get("code"));
      return errorMap;
   }

   public int requestCertificate(CBCertificate cert) throws CertificateAuthorityException,NoPermissionException {

      // we assume the caller has vetted the cn and altnames

      log.debug("ic new cert");
      int status = (-999);
      refreshSecrets();

      // build the soap request
      String csr = cert.pemRequest;
      while (csr.endsWith("\n")) {
         log.debug("removing csr trailing nl");
         csr = csr.replaceFirst("\\n$","");
      }
         
      String body = enrollBody.replaceFirst("AUTHDATA",authData).
         replaceFirst("ORGANDSECRET", orgAndSecret).
         replaceFirst("CSR",csr).
         replaceFirst("NUMSERVERS", String.valueOf(cert.numServer)).
         replaceFirst("SERVERTYPE", String.valueOf(cert.serverType)).
         replaceFirst("REQUESTOR", String.valueOf(cert.requestor)).
         replaceFirst("TERM", String.valueOf(cert.lifetime/12));

      // comodo allows separate specification of altnames.

      if (cert.formNames.size()>0) {
         cert.names = new Vector();
         cert.names.add(cert.cn);
         for (int i=0; i<cert.formNames.size(); i++) if (!cert.formNames.get(i).equals(cert.cn)) cert.names.add(cert.formNames.get(i));
      }
      String ans = cert.names.get(0);
      for (int i=1; i<cert.names.size(); i++) ans = ans + "," + cert.names.get(i);

      if (cert.names.size()>1) {
           body = body.replaceFirst("ALTNAME", "<subjAltNames>"+ans+"</subjAltNames>").replaceFirst("CERTTYPE", multiSSLType);
      } else if (cert.cn.startsWith("*.")) {
           body = body.replaceFirst("ALTNAME", "").replaceFirst("CERTTYPE", wildcardSSLType);;
      } else {
           body = body.replaceFirst("ALTNAME", "").replaceFirst("CERTTYPE", singleSSLType);;
      }

      log.debug("request: [" + body + "]");

      try {
         Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         // log.debug("ret: " + resp.toString());
         Element rsp = XMLHelper.getElementByName(resp, "enrollResponse");
         Element ret = XMLHelper.getElementByName(rsp, "return");
         status = Integer.parseInt(ret.getTextContent());
      } catch (WebClientException e) {
         throw new CertificateAuthorityException("incommon retrieve:" + e.getMessage());
      }

      log.debug("status: " + status);
      if (status<0) {
          if (status==(-16)) throw new NoPermissionException("InCommon says no permission.");
          else if (status==(-25)) throw new NoPermissionException("InCommon says DCV expired or not validated.");
          else throw new CertificateAuthorityException(String.valueOf(status));
      }
      cert.status = CBCertificate.CERT_STATUS_REQUESTED;
      cert.caId = status;
      return status;
   }

   public int getRequestStatus(CBCertificate cert) throws CertificateAuthorityException {
      log.debug("get cert status for " + cert.caId);
      refreshSecrets();
      String body = getCollectStatusBody.replaceFirst("AUTHDATA",authData).replaceFirst("ID", String.valueOf(cert.caId));
      int status = 0;
      try {
         Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element cr = XMLHelper.getElementByName(resp, "getCollectStatusResponse");
         Element ret = XMLHelper.getElementByName(cr, "return");
         status = Integer.parseInt(ret.getTextContent());
      } catch (WebClientException e) {
         throw new CertificateAuthorityException("incommon retrieve:" + e.getMessage());
      }
      log.debug("status: " + status);
      if (status<0) throw new CertificateAuthorityException(String.valueOf(status));
      if (status==0 && cert.status!=CBCertificate.CERT_STATUS_RENEWING &&
              cert.status!=CBCertificate.CERT_STATUS_DECLINED) cert.status = CBCertificate.CERT_STATUS_REQUESTED;
      if (status==1 || status==2) cert.status = CBCertificate.CERT_STATUS_ISSUED;
      return status;
   }

   public int renewCertificate(CBCertificate cert) throws CertificateAuthorityException {
      log.debug("renew " + cert.caId);
      refreshSecrets();
      String body = renewBody.replaceFirst("AUTHDATA",authData).replaceFirst("RENEWID", Integer.toString(cert.caId));
      int status = 0;
      try {
         Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element cr = XMLHelper.getElementByName(resp, "renewByIdResponse");
         Element ret = XMLHelper.getElementByName(cr, "return");
         status = Integer.parseInt(ret.getTextContent());
      } catch (WebClientException e) {
         throw new CertificateAuthorityException("incommon retrieve:" + e.getMessage());
      }
      log.debug("status: " + status);
      if (status<0) throw new CertificateAuthorityException(String.valueOf(status));
      // success returns the enrollment id, ostensibly a signed long, per Comodo.
      // This is already an int which should be big enough for a while.  2017-12-11 mattjm
      if ( 99999 < status && status < Integer.MAX_VALUE) cert.status = CBCertificate.CERT_STATUS_RENEWING;
      return 0;  //zero used to be the success code--if we got back an enrollment id above then it worked.
   }
   public int getRenewStatus(CBCertificate cert) {
      return 0;
   }

   // notify interested parties

   private void sendNotices(CBCertificate cert) {
       String id = String.valueOf(cert.id);
       cert.getHistory();
       if (cert.history.size()==0) {
          log.error("cert " + cert.id + " no history??");
          return;
       }
       CBHistory last = cert.history.get(cert.history.size()-1);

       IamMailMessage msg = new IamMailMessage(certIssuedMessage);
       msg.setSubstitutions(cert.cn, id, "InCommon");

       msg.setTo(last.netid + "@uw.edu");
       log.debug("mail to " + last.netid);
       String detail = "  Common name:  " + cert.cn + "\n";
       for (int i=0;i<cert.names.size(); i++) detail = detail + "  Alt name:     " + cert.names.get(i) + "\n";
       for (int i=0; i<cert.history.size(); i++) {
           CBHistory h = cert.history.get(i);
           if (h.event==1) detail = detail + "  Requested:    " + h.eventTime.toString() + " by " + h.netid + "\n";
           if (h.event==2) detail = detail + "  Renewed:      " + h.eventTime.toString() + " by " + h.netid + "\n";
           if (h.event==3) detail = detail + "  Revoked:      " + h.eventTime.toString() + " by " + h.netid + "\n";
       }
       if (cert.expires!=null) detail = detail + "  Expires:      " + cert.expires.toString() + "\n";
       detail = detail + "  InCommon ID:  " + String.valueOf(cert.caId) + "\n";
       String text = msg.getText();
       msg.setText(text.replaceAll("DETAIL",detail));
            
       iamMailSender.sendWithOwnerCc(msg, dnsVerifier, cert.names);

       // notify watchers if they're there
       if (certWatcherMessage!=null) {
          msg = new IamMailMessage(certWatcherMessage);
          msg.setSubstitutions(cert.cn, id, "InCommon");
          iamMailSender.send(msg);
       }
   }


   /* thread to watch for activity on waiting certs */

   class ActivityWatcher extends Thread {

       // sleep, return true if interrupted
       private boolean sleepOrInterrupt() {
          try {
             if (isInterrupted()) {
                log.info("interrupted during processing");
                return true;
             }
             Thread.sleep(refreshInterval * 1000);
          } catch (InterruptedException e) {
             log.info("ic watcher sleep interrupted");
             return true;
          }
          return false;
       }
       public void run() {
          log.debug("ic watcher running: interval = " + refreshInterval);
          if (sleepOrInterrupt()) return;  // allow other classes to init

          while (true) {
             log.debug("ic watcher checking...");

             // get waiting certs
             List<CBCertificate> certs = cbRegistry.getWaitingCertificates(CBCertificate.IC_CA);
             Iterator<CBCertificate> cit = certs.iterator();
             while (cit.hasNext()) {
                CBCertificate cert = cit.next();
                int status = 0;
                try {
                   status = getCertificate(cert);
                } catch (CertificateAuthorityException ex) {
                   log.error("checking on cert " + cert.cn + " error " + ex.getMessage());
                   continue;
                } catch (CBNotFoundException ex) {
                   log.error("checking on cert " + cert.cn + " error " + ex.getMessage());
                   continue;
                }
                log.debug("status of " + cert.cn + " = " + status);
             }
             if (sleepOrInterrupt()) break;
          }
       }
   }

  // reread secrets file if changed
   public void refreshSecrets() {
      try {
         File f = new File(authDataFile);
         if (authDataModified < f.lastModified()) {
            log.debug("refreshing authdata");
            StringWriter sw = new StringWriter();
            IOUtils.copy(new FileInputStream(f), sw);
            authData = sw.toString().replaceAll("\n","");
            Document authDoc;
            try {
               InputSource is = new InputSource(new StringReader(authData));
               authDoc = builder.parse(is);
               String loginUri = authDoc.getElementsByTagName("customerLoginUri").item(0).getTextContent();
               String loginId = authDoc.getElementsByTagName("login").item(0).getTextContent();
               String loginPw = authDoc.getElementsByTagName("password").item(0).getTextContent();
               authContentHdrMap = new HashMap<String, String>() {{
                  put("login", loginId);
                  put("password", loginPw);
                  put("customerUri", loginUri);
               }};
            } catch (SAXException e) {
               throw new RuntimeException(e);
            }
            authDataModified = f.lastModified();
         }
         f = new File(orgAndSecretFile);
         if (orgAndSecretModified < f.lastModified()) {
            log.debug("refreshing organdsecret");
            StringWriter sw = new StringWriter();
            IOUtils.copy(new FileInputStream(f), sw);
            orgAndSecret = sw.toString().replaceAll("\n","");
            orgAndSecretModified = f.lastModified();
         }
      } catch (IOException e) {
         log.error("could not read secrets: " + e);
      }
   }

   public void init() {
      log.debug("init");
      refreshSecrets();
      if (watchForActivity) {
         activityWatcher = new Thread(new ActivityWatcher());
         activityWatcher.start();
      }
   }

   public void cleanup() {
      log.info("IC cert interface got signal to cleanup");
      if (activityWatcher!=null) activityWatcher.interrupt();
   }

   public void setWebClient(WebClient v) {
      webClient = v;
   }
   public void setWatchForActivity(boolean v) {
      watchForActivity = v;
   }
   public void setCbRegistry(CBRegistry v) {
      cbRegistry = v;
   }
   public void setDnsVerifier(DNSVerifier v) {
      dnsVerifier = v;
   }
   public void setIamMailSender(IamMailSender v) {
      iamMailSender = v;
   }
   public void setCertIssuedMessage(IamMailMessage v) {
      certIssuedMessage = v;
   }
   public void setCertWatcherMessage(IamMailMessage v) {
      certWatcherMessage = v;
   }
   public void setRefreshInterval(int v) {
      refreshInterval = v;
   }
   public void setAuthDataFile(String v) {
      authDataFile = v;
   }
   public void setOrgAndSecretFile(String v) {
      orgAndSecretFile = v;
   }
   public void setSoapUrl(String v) {
      soapUrl = v;
   }
}
