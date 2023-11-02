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

import edu.washington.iam.ws.cabroker.exception.CBParseException;
import edu.washington.iam.ws.cabroker.registry.CBCertificate;
import java.io.IOException;
import java.io.StringReader;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PEMHelper {

  private static final Logger log = LoggerFactory.getLogger(PEMHelper.class);

  /* extract some info from the submitted CSR */

  private static final String COUNTRY = "2.5.4.6";
  private static final String STATE = "2.5.4.8";
  private static final String ORGANIZATION = "2.5.4.10";
  private static final String COMMON_NAME = "2.5.4.3";

  private static String getX500Field(String asn1ObjectIdentifier, X500Name x500Name) {
    log.debug("looking for [" + asn1ObjectIdentifier + "]");
    RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));
    for (RDN item : rdnArray) {
      // log.debug("RDN: size=" +  item.size());
      AttributeTypeAndValue[] atvArray = item.getTypesAndValues();
      for (AttributeTypeAndValue atv : atvArray) {
        // log.debug("type id=[" + atv.getType().getId() + "]");
        // log.debug("type string=" + atv.getType().toString());
        // log.debug("value string=" + atv.getValue().toString());
        if (atv.getType().getId().equals(asn1ObjectIdentifier)) {
          log.debug(".. have value = " + atv.getValue().toString());
          return atv.getValue().toString();
        }
      }
    }
    return null;
  }

  public static int parseCsr(CBCertificate cert) throws CBParseException {

    PKCS10CertificationRequest request = null;
    try {
      PEMParser pRd = new PEMParser(new StringReader(cert.pemRequest));
      request = (PKCS10CertificationRequest) pRd.readObject();
      if (request == null) throw new CBParseException("invalid CSR (request)");

      X500Name dn = request.getSubject();
      if (dn == null) throw new CBParseException("invalid CSR (dn)");
      log.debug("parseCsr: dn=" + dn.toString());
      cert.dn = dn.toString();
      try {
        String x = getX500Field(COMMON_NAME, dn);
        log.debug("cn: " + x);
        cert.cn = x;
        cert.names.add(cert.cn.toLowerCase()); // first entry for names is always cn
        x = getX500Field(COUNTRY, dn);
        log.debug("country: " + x);
        cert.dnC = x;
        x = getX500Field(STATE, dn);
        log.debug("state: " + x);
        cert.dnST = x;
        x = getX500Field(ORGANIZATION, dn);
        log.debug("org: " + x);
        cert.dnO = x;
      } catch (Exception e) {
        log.debug("get cn error: " + e);
        throw new CBParseException(
            "invalid CSR--check for missing State, Country or Organization.");
      }

    } catch (Exception e) {
      log.debug("request DN parse exception: " + e);
      throw new CBParseException("e.getMessage()");
    }
    // see if we've got alt names (in extensions)

    Attribute[] attrs = request.getAttributes();
    for (Attribute attr : attrs) {
      try {
        Extensions extensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
        GeneralNames gns =
            GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        GeneralName[] names = gns.getNames();
        for (int k = 0; k < names.length; k++) {
          if (names[k].getTagNo() == GeneralName.dNSName) {
            log.debug("adding altname: " + names[k].getName());
            cert.names.add(names[k].getName().toString().toLowerCase());
          } else if (names[k].getTagNo() == GeneralName.iPAddress) {
            // org.bouncycastle.asn1.x509.GeneralName *is* an ASN1Object (subclass), and this method
            // - doesn't have any effect (result is never assigned), and
            // - org.bouncycastle.asn1.x509.GeneralName no longer has this method
            // names[k].toASN1Object();
            log.debug("ignoring altip: " + names[k].getName());
          }
        }
      } catch (Exception e) {
        log.debug("ignoring request ATTR parse exception: " + e);
        // throw new CBParseException("e.getMessage()");
      }
    }

    // note key size

    try {
      JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(request);
      PublicKey pk = jcaRequest.getPublicKey();
      log.debug("key alg/fmt = " + pk.getAlgorithm() + " / " + pk.getFormat());
      if (pk.getAlgorithm().equals("RSA")) {
        RSAPublicKey rpk = (RSAPublicKey) pk;
        cert.keySize = rpk.getModulus().bitLength();
        log.debug("key size = " + cert.keySize);
      }

    } catch (Exception e) {
      log.debug("request KEY parse exception: " + e);
      throw new CBParseException("e.getMessage()");
    }
    return 1;
  }

  /* extract some info from the Cert */

  public static int parseCert(CBCertificate cert) {

    try {
      PEMParser pRd = new PEMParser(new StringReader(cert.pemCert));
      // X509Certificate x509 = (X509Certificate)pRd.readObject();
      X509CertificateHolder x509h = (X509CertificateHolder) pRd.readObject();
      X509Certificate x509 =
          new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509h);
      cert.issued = x509.getNotBefore();
      cert.expires = x509.getNotAfter();
      log.debug("pem expires = " + cert.expires);

      cert.setSerialNumber(x509.getSerialNumber());

      X500Principal prin = x509.getSubjectX500Principal();
      cert.dn = prin.toString();
      log.debug("principal = " + cert.dn);

      // see if we've got alt names (in extensions)

      Collection<List<?>> ans = x509.getSubjectAlternativeNames();

      log.debug("ans size = " + ans.size());
      Iterator it = ans.iterator();
      while (it.hasNext()) {
        List an = (List) it.next();
        if (an.size() == 2) {
          log.debug("an0=" + an.get(0).toString() + " an1=" + an.get(1).toString());
          if (an.get(0) instanceof Integer && an.get(1) instanceof String) {
            cert.names.add((String) an.get(1));
          }
        }
      }
      if (cert.cn.equals("") && cert.names.size() > 0) cert.cn = cert.names.get(0);

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
