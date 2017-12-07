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

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Vector;
import java.util.Iterator;
import java.io.StringWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;


import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.io.IOUtils;

import org.bouncycastle.util.encoders.Base64;

import edu.washington.iam.tools.WebClient;
import edu.washington.iam.tools.WebClientException;
import edu.washington.iam.tools.XMLHelper;
import edu.washington.iam.ws.cabroker.util.PEMHelper;

import edu.washington.iam.ws.cabroker.registry.CBCertificate;
import edu.washington.iam.ws.cabroker.registry.CBHistory;
import edu.washington.iam.ws.cabroker.registry.CBRegistry;

import edu.washington.iam.tools.DNSVerifier;
import edu.washington.iam.tools.DNSVerifyException;
import edu.washington.iam.tools.IamMailMessage;
import edu.washington.iam.tools.IamMailSender;

import edu.washington.iam.ws.cabroker.ca.CertificateAuthority;
import edu.washington.iam.ws.cabroker.exception.CertificateAuthorityException;
import edu.washington.iam.ws.cabroker.exception.CBNotFoundException;
import edu.washington.iam.ws.cabroker.exception.NoPermissionException;

public class ICCertificateAuthority implements CertificateAuthority {

   private final Logger log =   LoggerFactory.getLogger(getClass());

   private String customerLoginUri = "InCommon";
   private String login;
   private String password;
   
   private WebClient webClient;
   private CBRegistry cbRegistry;
   private DNSVerifier dnsVerifier;
   private IamMailSender iamMailSender;
   private IamMailMessage certIssuedMessage = null;
   private IamMailMessage certWatcherMessage = null;

   private static String soapUrl = "https://cert-manager.com:443/ws/EPKIManagerSSL";
   private static String soapAction = "";
   private static boolean initialized = false;
   private static String timeoutMessage = "No response from InCommon.  The service may be down temporarily. Please try again later.";

   private static boolean watchForActivity = false;
   private Thread activityWatcher = null;
   private int refreshInterval = 0;

   //TODO
   //private static String authDataFile = "/data/local/etc/comodo.pw";
   //private static String orgAndSecretFile = "/data/local/etc/comodo.os";
   private static String authDataFile = "C:\\Users\\mattjm\\Documents\\spregworking\\incommoncert\\comodo.pw";
   private static String orgAndSecretFile = "C:\\Users\\mattjm\\Documents\\spregworking\\incommoncert\\comodo.os";
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

   private static String getCustomerCertTypesBody = "<tns:getCustomerCertTypes xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
        "</tns:getCustomerCertTypes>";

   private static String collectBody = "<tns:collect xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<id>ID</id><formatType>1</formatType></tns:collect>";

   private static String collectPKCS7 = "<tns:collect xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<id>ID</id><formatType>3</formatType></tns:collect>";

   private static String collectRenewedBody = "<tns:collectRenewed xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<renewId>ID</renewId><formatType>1</formatType></tns:collectRenewed>";

   private static String collectRenewedPKCS7 = "<tns:collectRenewed xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<renewId>ID</renewId><formatType>3</formatType></tns:collectRenewed>";

   private static String getCollectStatusBody = "<tns:getCollectStatus xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<id>ID</id></tns:getCollectStatus>";

   // SHA-2 types
   private String singleSSLType = "<certType><id>224</id><name>InCommon SSL (SHA-2)</name>" +
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";
   
   private String multiSSLType = "<certType><id>226</id><name>InCommon Multi Domain SSL (SHA-2)</name>" +
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";

   private String wildcardSSLType = "<certType><id>227</id><name>InCommon Wildcard SSL Certificate (SHA-2)</name>" +
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";

/** SHA-1 types 
   private String singleSSLType = "<certType><id>62</id><name>InCommon SSL</name>" +
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";

   private String multiSSLType = "<certType><id>64</id><name>InCommon Multi Domain SSL</name>" + 
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";

   private String wildcardSSLType = "<certType><id>63</id><name>InCommon Wildcard SSL Certificate</name>" + 
        "<terms>1</terms><terms>2</terms><terms>3</terms></certType>";

**/

   private static String enrollBody = "<tns:enroll xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "ORGANDSECRET" +
       "<csr>CSR</csr>" +
       "<phrase>whatsthisfor</phrase>" +
       "ALTNAME" +
       "CERTTYPE" +
       "<numberServers>NUMSERVERS</numberServers>" +
       "<serverType>SERVERTYPE</serverType>" +
       "<term>TERM</term>" +
       "<comments>requested by REQUESTOR</comments>" +
       "</tns:enroll>";

       // "<subjAltNames xsi:type=\"xsd:string\">ALTNAMES</subjAltNames>" +
   
   private static String renewBody = "<tns:renewById xmlns:tns=\"http://ssl.ws.epki.comodo.com/\">AUTHDATA" +
       "<id>RENEWID</id></tns:renewById>";

 
   public int getCertificate(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException {
      log.debug("get cert for " + cert.caId);
      
      if (cert.renewId!=null && cert.renewId.length()>0 &&
          cert.status!=CBCertificate.CERT_STATUS_DECLINED) return getRenewedCertificate(cert); 

      cert.pemCert = null;
      int status = (-999);

      int oldStatus = cert.status;
      if (oldStatus==CBCertificate.CERT_STATUS_REVOKED) return oldStatus;
      refreshSecrets();
    
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
            PEMHelper.parseCert(cert);
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
            // sendNotices(cert);
         }
         cert.updateDB();
         if (status==(-21)) cert.addHistory(CBHistory.CB_HIST_REV, new Date(), "somebody");

      return status;
   }

   // the cert has already been gotten.  only update for errors
   public String getCertificatePKCS7(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException {
      log.debug("get plcs7 for " + cert.caId);

      if (cert.renewId!=null && cert.renewId.length()>0) return getRenewedCertificatePKCS7(cert);  // always seems to work

      int status = (-999);
      String pkcs7 = null;
      refreshSecrets();
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

      return pkcs7;
   }


   public int getRenewedCertificate(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException {
      log.debug("get renewed cert for " + cert.caId + " renewId=" + cert.renewId + " status=" + cert.status);
      cert.pemCert = null;
      int status = (-999);
      if (cert.renewId!=null && cert.renewId.length()==0) return status; // shouldn't happen

      int oldStatus = cert.status;
      if (oldStatus==CBCertificate.CERT_STATUS_REVOKED) return oldStatus;
      refreshSecrets();
    
         String body = collectRenewedBody.replaceFirst("AUTHDATA",authData).replaceFirst("ID", String.valueOf(cert.renewId));
         // log.debug("request: " + body);
         Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element cr = XMLHelper.getElementByName(resp, "collectRenewedResponse");
         if (cr==null) {
            log.error("ic no collectRenewedResponse!");
            throw new CertificateAuthorityException("missing collectRenewedResponse");
         }
         Element ret = XMLHelper.getElementByName(cr, "return");
         if (ret==null) {
            log.error("ic no ret!");
            throw new CertificateAuthorityException("missing return");
         }
         Element sc = XMLHelper.getElementByName(ret, "errorCode");
         if (sc==null) {
            log.error("ic no sc!");
            throw new CertificateAuthorityException("missing errorcode");
         }

         status = Integer.parseInt(sc.getTextContent());
         log.debug("status: " + status);
         if (status==0) cert.status = CBCertificate.CERT_STATUS_ISSUED;
         else if (status==(-6)) cert.status = CBCertificate.CERT_STATUS_DECLINED;

         if (status==0) {
            Element data = XMLHelper.getElementByName(ret, "data");
            String b64 = data.getTextContent();
            cert.pemCert = new String(Base64.decode(b64));
            PEMHelper.parseCert(cert);
         }
         if (status==(-1) || status==(-5)) {
            cert.status = CBCertificate.CERT_STATUS_RENEWING;
         } else if (status==(-6)) {
            cert.status = CBCertificate.CERT_STATUS_DECLINED;
         } else if (status==(-2)) {
            // have seen this come back when an expired cert was renewed
            if (cert.status != CBCertificate.CERT_STATUS_RENEWING) {
               cert.renewId = null;
               return getCertificate(cert);  // revocation or expired
            }
         } 
         if (status==0 && oldStatus!=CBCertificate.CERT_STATUS_ISSUED) {
            // sendNotices(cert);
            cert.status = CBCertificate.CERT_STATUS_ISSUED;
         }
         cert.updateDB();


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
    
         String body = collectRenewedPKCS7.replaceFirst("AUTHDATA",authData).replaceFirst("ID", String.valueOf(cert.renewId));
         Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element cr = XMLHelper.getElementByName(resp, "collectRenewedResponse");
         Element ret = XMLHelper.getElementByName(cr, "return");
         Element sc = XMLHelper.getElementByName(ret, "errorCode");

         status = Integer.parseInt(sc.getTextContent());
         log.debug("status: " + status);

         if (status==(-4)) throw new CBNotFoundException("not found");
         if (status==(-1) || status==(-5)) throw new CertificateAuthorityException("renewing");
         if (status<0) throw new CertificateAuthorityException(String.valueOf(status));

         if (status==0) {
            Element data = XMLHelper.getElementByName(ret, "data");
            String b64 = data.getTextContent();
            pkcs7 = new String(Base64.decode(b64));
         }

      return pkcs7;
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

      if (cert.cn.startsWith("*.")) {
           body = body.replaceFirst("ALTNAME", "").replaceFirst("CERTTYPE", wildcardSSLType);;
      } else if (cert.names.size()>1) {
           body = body.replaceFirst("ALTNAME", "<subjAltNames>"+ans+"</subjAltNames>").replaceFirst("CERTTYPE", multiSSLType);
      } else {
           body = body.replaceFirst("ALTNAME", "").replaceFirst("CERTTYPE", singleSSLType);;
      }

      // log.debug("request: [" + body + "]");

         Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         // log.debug("ret: " + resp.toString());
         Element rsp = XMLHelper.getElementByName(resp, "enrollResponse");
         Element ret = XMLHelper.getElementByName(rsp, "return");
         status = Integer.parseInt(ret.getTextContent());

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
      Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
      if (resp==null) throw new CertificateAuthorityException("IO error to CA");
      Element cr = XMLHelper.getElementByName(resp, "getCollectStatusResponse");
      Element ret = XMLHelper.getElementByName(cr, "return");
      int status = Integer.parseInt(ret.getTextContent());
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
      Element resp = webClient.doSoapRequest(soapUrl, soapAction, body);
      if (resp==null) throw new CertificateAuthorityException("IO error to CA");
      Element cr = XMLHelper.getElementByName(resp, "renewByIdResponse");
      Element ret = XMLHelper.getElementByName(cr, "return");
      int status = Integer.parseInt(ret.getTextContent());
      log.debug("status: " + status);
      if (status<0) throw new CertificateAuthorityException(String.valueOf(status));
      if (status==0) cert.status = CBCertificate.CERT_STATUS_RENEWING;
      return status;
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

   public void setCustomerLoginUri(String v) {
      customerLoginUri = v;
   }
   public void setLogin(String v) {
      login = v;
   }
   public void setPassword(String v) {
      password = v;
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
   public void setTimeoutMessage(String v) {
      timeoutMessage = v;
   }

}
