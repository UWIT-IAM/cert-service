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

package edu.washington.iam.ws.cabroker.util;

import java.lang.Exception;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Date;
import java.util.Enumeration;
import java.util.Collection;
import java.io.StringReader;
import java.io.IOException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import javax.security.auth.x500.X500Principal;


import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import edu.washington.iam.ws.cabroker.registry.CBCertificate;
import edu.washington.iam.ws.cabroker.exception.CBParseException;

public final class PEMHelper {

   private static final Logger log =  LoggerFactory.getLogger(PEMHelper.class);

   /* extract some info from the submitted CSR */

   public static int parseCsr(CBCertificate cert) throws CBParseException {

      try {
         PEMReader  pRd = new PEMReader(new StringReader(cert.pemRequest));
         log.debug("pRd ok");
         PKCS10CertificationRequest request = (PKCS10CertificationRequest)pRd.readObject();
         log.debug("req ok");
         if (request==null) throw new CBParseException("invalid CSR (request)");
         CertificationRequestInfo info = request.getCertificationRequestInfo();
         log.debug("info ok");
         if (info==null) throw new CBParseException("invalid CSR (info)");
   
         X509Name dn = info.getSubject();
         if (dn==null) throw new CBParseException("invalid CSR (dn)");
         log.debug("dn=" + dn.toString());
         cert.dn = dn.toString();
         try {
            List cns = dn.getValues(X509Name.CN);
            if (cns.size()!=1) throw new CBParseException("invalid CSR"); 
            cert.cn = (String)(cns.get(0));
            log.debug("cn=" + cert.cn);
            cert.names.add(cert.cn.toLowerCase());   // first entry for names is always cn
            cns = dn.getValues(X509Name.C);
            cert.dnC = (String)(cns.get(0));
            cns = dn.getValues(X509Name.ST);
            cert.dnST = (String)(cns.get(0));
            cns = dn.getValues(X509Name.O);
            cert.dnO = (String)(cns.get(0));
         } catch (Exception e) {
            log.debug("get cn error: " + e);
            throw new CBParseException("invalid CSR--check for missing State, Country or Organization.");
         }

         // see if we've got alt names (in extensions)

         ASN1Set attrs = info.getAttributes();
         if (attrs!=null) {
          for (int a=0; a<attrs.size(); a++) {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(a)); 
            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
      
               // is the extension
               X509Extensions extensions = X509Extensions.getInstance(attr.getAttrValues().getObjectAt(0)); 
    
               // get the subAltName extension
               DERObjectIdentifier sanoid = new DERObjectIdentifier(X509Extensions.SubjectAlternativeName.getId());
               X509Extension  xext = extensions.getExtension(sanoid);
               if (xext!=null) {
                  log.debug("processing altname extensions");
                  ASN1Object asn1 = X509Extension.convertValueToObject(xext);
                  Enumeration dit = DERSequence.getInstance(asn1).getObjects();
                  while (dit.hasMoreElements()) {
                     GeneralName gn = GeneralName.getInstance(dit.nextElement());
                     log.debug("altname tag=" + gn.getTagNo());
                     log.debug("altname name=" + gn.getName().toString());
                     if (gn.getTagNo()==GeneralName.dNSName) cert.names.add( gn.getName().toString().toLowerCase());
                  }
               }
         
            }
          }
         }
        
         // check key size
         PublicKey pk = request.getPublicKey();
         log.debug("key alg = " + pk.getAlgorithm());
         log.debug("key fmt = " + pk.getFormat());
         if (pk.getAlgorithm().equals("RSA")) {
            RSAPublicKey rpk = (RSAPublicKey) pk;
            cert.keySize = rpk.getModulus().bitLength();
            log.debug("key size = " + cert.keySize);
         }
         

      } catch (IOException e) {
        log.debug("ioerror: " + e);
        throw new CBParseException("invalid CSR " + e.getMessage());
      } catch (Exception e) {
        log.debug("excp: " + e);
        throw new CBParseException("invalid CSR");
      }
      return 1;
   }


   /* extract some info from the Cert */

   public static int parseCert(CBCertificate cert) {

      try {
         PEMReader  pRd = new PEMReader(new StringReader(cert.pemCert));
         X509Certificate x509 = (X509Certificate)pRd.readObject();

         cert.issued = x509.getNotBefore();
         cert.expires = x509.getNotAfter();
         log.debug("pem expires = " + cert.expires);

         X500Principal prin = x509.getSubjectX500Principal();
         cert.dn = prin.toString();
         log.debug("principal = " + cert.dn);

         // see if we've got alt names (in extensions)

         Collection<List<?>> ans = x509.getSubjectAlternativeNames();

         log.debug("ans size = " + ans.size());
         Iterator it = ans.iterator();
         while (it.hasNext()) {
            List an = (List)it.next();
            if (an.size()==2) {
               log.debug("an0="+an.get(0).toString() + " an1=" + an.get(1).toString());
               if (an.get(0) instanceof Integer && an.get(1) instanceof String ) {
                  cert.names.add((String)an.get(1));
               }
            }
         }
         if (cert.cn.equals("") && cert.names.size()>0) cert.cn = cert.names.get(0);
            
         // check for expired
         try {
            x509.checkValidity();
         } catch (CertificateExpiredException e) {
           cert.status = CBCertificate.CERT_STATUS_EXPIRED;
         } catch (CertificateNotYetValidException e) {
           log.debug("not yet valid?");
         }

         // get the key size
         PublicKey pk = x509.getPublicKey();
         if (pk.getAlgorithm().equals("RSA")) {
            RSAPublicKey rpk = (RSAPublicKey) pk;
            cert.keySize = rpk.getModulus().bitLength();
            log.debug("pub key size = " + cert.keySize);
         }

         // get the sig alg
         cert.sigAlg = x509.getSigAlgName();
         log.debug("signature: " + cert.sigAlg);

         return 1;

      } catch (IOException e) {
        log.debug("ioerror: " + e);
      } catch (Exception ex) {
        log.debug("excp: " + ex);
      }
      return 0;
   }
}
