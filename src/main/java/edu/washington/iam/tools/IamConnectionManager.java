/* ========================================================================
 * Copyright (c) 2011 The University of Washington
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

package edu.washington.iam.tools;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.net.MalformedURLException;

import javax.net.ssl.TrustManager;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.FileInputStream;
import java.io.IOException;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Key;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;


/**
 * Build a connection manager from PEM ca, cert, and key files
 */

public class IamConnectionManager {

   private String caFilename;
   private String certFilename;
   private String keyFilename;

   private SSLSocketFactory socketFactory;
   private TrustManager[] trustManagers;
   private KeyManager[] keyManagers;
   private KeyStore keyStore;
   private KeyStore trustStore;
   private SchemeRegistry schemeRegistry;
   private ThreadSafeClientConnManager connectionManager;

   private static Logger log = LoggerFactory.getLogger(IamConnectionManager.class);
   
   public IamConnectionManager(String caFile, String certFile, String keyFile) {
      log.debug("create connection manager");
      caFilename = caFile; 
      certFilename = certFile; 
      keyFilename = keyFile; 
      String protocol = "https";
      int port = 443;

      initManagers();

      try {
         SSLContext ctx = SSLContext.getInstance("TLS");
         ctx.init(keyManagers, trustManagers, null);
         socketFactory = new SSLSocketFactory(ctx);
         Scheme scheme = new Scheme(protocol, socketFactory, port);
         schemeRegistry = new SchemeRegistry();
         schemeRegistry.register(scheme);

         log.debug("create conn mgr");
         connectionManager = new ThreadSafeClientConnManager(new BasicHttpParams(),schemeRegistry);

      } catch (Exception e) {
         log.error("sf error: " + e);
      }
   }

   
   public SSLSocketFactory getSocketFactory() {
       log.debug("sr get sock factory");
       return socketFactory;
   }
   public SchemeRegistry getSchemeRegistry() {
       log.debug("sr get scheme reg");
       return schemeRegistry;
   }
   public ClientConnectionManager getConnectionManager() {
       return (ClientConnectionManager) connectionManager;
   }
      
   protected void initSocketFactory() {
       log.debug("sr sock factory init");

       TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
           public X509Certificate[] getAcceptedIssuers() {
               return null;
           }

           public void checkClientTrusted(X509Certificate[] certs, String authType) {
               return;
           }

           public void checkServerTrusted(X509Certificate[] certs, String authType) {
               return;
           }
       }};

       try {
           SSLContext sc = SSLContext.getInstance("SSL");
           // sc.init(keyManagers, trustManagers, new java.security.SecureRandom());
           sc.init(keyManagers, trustAllCerts, new java.security.SecureRandom());
           // socketFactory = sc.getSocketFactory();
       } catch (Exception e) {
           log.error("mango initSF error: " + e);
       }
   }

   
   protected void initManagers() {

       // trust managers
/**
       try {
           TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

           X509Certificate cert = null;
           if (caFilename!=null) cert = readCertificate(caFilename);
           log.debug("init trust mgr " + cert);
           trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
           trustStore.load(null, null);
           trustStore.setCertificateEntry("CACERT", cert);
           tmf.init(trustStore);
           trustManagers = tmf.getTrustManagers();
       } catch (Exception e) {
           log.error("cacert error: " + e);
       }
 **/
     trustManagers = new TrustManager[] { new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {
            return;
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
            return;
        }
    }};



       // key managers
       if (certFilename != null && keyFilename != null) {
           try {
              KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
              keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
              keyStore.load(null, null);

              X509Certificate cert = readCertificate(certFilename);
              PKCS1 pkcs = new PKCS1();
              PrivateKey key = pkcs.readKey(keyFilename);

              X509Certificate[] chain = new X509Certificate[1];
              chain[0] = cert;
              keyStore.setKeyEntry("CERT", (Key) key, "pw".toCharArray(), chain);

              kmf.init(keyStore, "pw".toCharArray());
              keyManagers = kmf.getKeyManagers();
           } catch (Exception e) {
              log.error("cert/key error: " + e);
           }
       }

   }

    protected X509Certificate readCertificate(String filename) {
        FileInputStream file;
        X509Certificate cert;
        try {
            file = new FileInputStream(filename);
        } catch (IOException e) {
            log.error("ldap source bad cert file: " + e);
            return null;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(file);
        } catch (CertificateException e) {
            log.error("ldap source bad cert: " + e);
            return null;
        }
        return cert;
    }
   
}
