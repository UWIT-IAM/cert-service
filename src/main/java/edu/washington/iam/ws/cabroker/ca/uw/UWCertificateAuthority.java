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

package edu.washington.iam.ws.cabroker.ca.uw;

import java.io.Serializable;
import java.util.List;
import java.util.ArrayList;
import java.util.Vector;
import java.util.Iterator;
import java.io.StringWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.NullPointerException;
import java.net.SocketTimeoutException;


import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.io.IOUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

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

public class UWCertificateAuthority implements CertificateAuthority {

   private final Logger log =   LoggerFactory.getLogger(getClass());

   private String authHeader;
   
   private WebClient webClient;
   private CBRegistry cbRegistry;
   private DNSVerifier dnsVerifier;
   private IamMailSender iamMailSender;
   private IamMailMessage certIssuedMessage = null;
   private IamMailMessage certWatcherMessage = null;
   private static boolean watchForActivity = false;
   private Thread activityWatcher = null;
   private int refreshInterval = 0;

   private static String uwcaUrl = "";
   private static boolean initialized = false;
   private static String timeoutMessage = "No response from the UWCA.  The service may be down temporarily. Please try again later.";

   public int getCertificate(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException {
      log.debug("get cert for " + cert.caId);
      cert.pemCert = null;
      int status = (-999);
      int oldStatus = cert.status;

      try {
         String url = uwcaUrl + "?req=get&rno=" + cert.caId;
         Element resp = webClient.doRestGet(url, authHeader);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element stat = XMLHelper.getElementByName(resp, "status");
         status = Integer.parseInt(stat.getTextContent());
         log.debug("status: " + status);
         if (status==404) throw new CBNotFoundException("not found. expired?");
         if (cert.status!=4 && status==1) cert.status = CBCertificate.CERT_STATUS_REQUESTED;
         if (status==2) cert.status = CBCertificate.CERT_STATUS_ISSUED;
         if (status==5) cert.status = CBCertificate.CERT_STATUS_REVOKED;
         if (status==0) cert.status = CBCertificate.CERT_STATUS_GONE;  // not found
         if (status==7) cert.status = CBCertificate.CERT_STATUS_EXPIRED;
         Element certE = XMLHelper.getElementByName(resp, "pem");
         if (certE!=null) cert.pemCert = certE.getTextContent();
         if (cert.pemCert!=null) PEMHelper.parseCert(cert);
         if (cert.status==CBCertificate.CERT_STATUS_EXPIRED) status = 7;  // got cert but it is expired

      } catch (NullPointerException e) {
         // due to invalid uwca response
         log.debug("get uwca excp: " + e);
         throw new CertificateAuthorityException("uwca retrieve failed");
      }

      if (status==2 && oldStatus!=2) {
         sendNotices(cert);
      }
      cert.updateDB();

      if (status==0) throw new CBNotFoundException("not found");
      return status;
   }

   public String getCertificatePKCS7(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException {
      log.debug("get plcs7 for " + cert.caId);
      int status = (-999);
      String pkcs7 = null;
      try {
         String url = uwcaUrl + "?req=pkcs7&rno=" + cert.caId;
         Element resp = webClient.doRestGet(url, authHeader);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element stat = XMLHelper.getElementByName(resp, "status");
         status = Integer.parseInt(stat.getTextContent());
         log.debug("status: " + status);
         if (status==404) throw new CBNotFoundException("not found");
         if (status==0) throw new CBNotFoundException("not found");
         Element pk = XMLHelper.getElementByName(resp, "pkcs7");
         pkcs7 = pk.getTextContent();

      } catch (NullPointerException e) {
         // due to invalid uwca response
         log.debug("get uwca excp: " + e);
         throw new CertificateAuthorityException("uwca pkcs7 retrieve failed");
      }

      return pkcs7;
   }



   public int requestCertificate(CBCertificate cert) throws CertificateAuthorityException,NoPermissionException {
      log.debug("req cert");
      int status = (-999);
      try {
         String url = uwcaUrl + "?req=new";
         List<NameValuePair> data = new ArrayList<NameValuePair>();
         data.add(new BasicNameValuePair("csr", cert.pemRequest));

         String ctyp = "webserver";
         if (cert.certType==2) ctyp = "client-server";
         String styp = "other";
         if (cert.serverType==2) styp = "Apache";
         else if (cert.serverType==13) styp = "IIS";
         else if (cert.serverType==14) styp = "IIS 5.x";
         else if (cert.serverType==24) styp = "tomcat";
         data.add(new BasicNameValuePair("notes", "Cert: " + ctyp + ", server: " + styp));
         data.add(new BasicNameValuePair("lifetime", String.valueOf(cert.lifetime)));

         Element resp = webClient.doRestPut(url, data, authHeader);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element stat = XMLHelper.getElementByName(resp, "status");
         status = Integer.parseInt(stat.getTextContent());
         log.debug("status: " + status);
         if (status==404) throw new CertificateAuthorityException("UWCA says: no permission");
         if (status==400) throw new CertificateAuthorityException("UWCA says: invalid request");
         if (cert.status!=4 && status==1) cert.status = CBCertificate.CERT_STATUS_REQUESTED;
         if (status==2) cert.status = CBCertificate.CERT_STATUS_ISSUED;
         Element reqno = XMLHelper.getElementByName(resp, "reqno");
         cert.caId = Integer.parseInt(reqno.getTextContent());
         log.debug("uwca reqno=" + cert.caId);
      } catch  (NullPointerException e) {
         // due to invalid uwca response
         log.debug("get uwca excp: " + e);
         throw new CertificateAuthorityException("uwca request failed");
      }
      return status;
   }


   public int getRequestStatus(CBCertificate cert) throws CertificateAuthorityException {
      return 1;
   }

   public int renewCertificate(CBCertificate cert) throws CertificateAuthorityException {
      log.debug("renew cert");
      int status = (-999);
      try {
         String url = uwcaUrl + "?req=renew&rno=" + cert.caId;
         List<NameValuePair> data = new ArrayList<NameValuePair>();

         Element resp = webClient.doRestPut(url, data, authHeader);
         if (resp==null) throw new CertificateAuthorityException("IO error to CA");
         Element stat = XMLHelper.getElementByName(resp, "status");
         status = Integer.parseInt(stat.getTextContent());
         log.debug("status: " + status);
         if (cert.status!=4 && status==6) cert.status = CBCertificate.CERT_STATUS_RENEWING;
         log.debug("uwca renew ok");
      } catch  (NullPointerException e) {
         // due to invalid uwca response
         log.debug("renew uwca excp: " + e);
         throw new CertificateAuthorityException("uwca renew failed");
      }
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
       msg.setSubstitutions(cert.cn, id, "UWCA");

       msg.setTo(last.netid + "@uw.edu");
       log.debug("mail to " + last.netid);
       String detail = "  Common name:  " + cert.cn + "\n";
       for (int i=1;i<cert.names.size(); i++) detail = detail + "  Alt name:     " + cert.names.get(i) + "\n";
       for (int i=0; i<cert.history.size(); i++) {
           CBHistory h = cert.history.get(i); 
           if (h.event==1) detail = detail + "  Requested:    " + h.eventTime.toString() + " by " + h.netid + "\n";
           if (h.event==2) detail = detail + "  Renewed:      " + h.eventTime.toString() + " by " + h.netid + "\n";
           if (h.event==3) detail = detail + "  Revoked:      " + h.eventTime.toString() + " by " + h.netid + "\n";
       }
       if (cert.expires!=null) detail = detail + "  Expires:      " + cert.expires.toString() + "\n";
       detail = detail + "  UWCA ID:  " + String.valueOf(cert.caId) + "\n";
       String text = msg.getText();
       msg.setText(text.replaceAll("DETAIL",detail));

       iamMailSender.sendWithOwnerCc(msg, dnsVerifier, cert.names);

       // notify watchers if they're there
       if (certWatcherMessage!=null) {
          msg = new IamMailMessage(certWatcherMessage);
          msg.setSubstitutions(cert.cn, id, "UWCA");
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
             log.info("uw watcher sleep interrupted");
             return true;
          }
          return false;
       }
       public void run() {
          log.debug("uw watcher running: interval = " + refreshInterval);
          if (sleepOrInterrupt()) return;  // allow other classes to init

          while (true) {
             log.debug("uw watcher checking...");

             // get waiting certs
             List<CBCertificate> certs = cbRegistry.getWaitingCertificates(CBCertificate.UW_CA);
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

   public void init() {
      log.debug("read pw");
      try {
         StringWriter sw = new StringWriter();
         IOUtils.copy(new FileInputStream(new File("/data/local/etc/uwca.pw")), sw);
         authHeader = sw.toString().replaceAll("\n","");
      } catch (IOException e) {
         log.error("could not read pw: " + e);
      }
      if (watchForActivity) {
         activityWatcher = new Thread(new ActivityWatcher());
         activityWatcher.start();
      }
   }

   public void cleanup() {
      log.info("UW cert interface got signal to cleanup");
      if (activityWatcher!=null) activityWatcher.interrupt();
   }

   public void setWebClient(WebClient v) {
      webClient = v;
   }

   public void setUwcaUrl(String v) {
      uwcaUrl = v;
   }

   public void setWatchForActivity(boolean v) {
      watchForActivity = v;
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
   public void setDnsVerifier(DNSVerifier v) {
      dnsVerifier = v;
   }

   public void setRefreshInterval(int v) {
      refreshInterval = v;
   }
   public void setCbRegistry(CBRegistry v) {
      cbRegistry = v;
   }
   public void setTimeoutMessage(String v) {
      timeoutMessage = v;
   }


}
