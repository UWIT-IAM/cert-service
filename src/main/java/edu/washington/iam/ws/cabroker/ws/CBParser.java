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

package edu.washington.iam.ws.cabroker.ws;

import java.lang.Exception;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Date;
import java.util.Enumeration;
import java.io.StringReader;
import java.io.IOException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

import java.security.cert.X509Certificate;

// import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;


import edu.washington.iam.ws.cabroker.registry.CBCertificate;

import  edu.washington.iam.ws.cabroker.exception.CBParseException;

import  edu.washington.iam.tools.XMLHelper;
import  edu.washington.iam.ws.cabroker.util.PEMHelper;


public final class CBParser {

   private static final Logger log =  LoggerFactory.getLogger(CBParser.class);

   /* process the submitted request info */

   public static CBCertificate parseRequest(Document doc) throws CBParseException {

      CBCertificate cert = new CBCertificate();

      Element req = doc.getDocumentElement();
      try {
         cert.ca = Integer.parseInt(req.getAttribute("certCa"));
         cert.certType = Integer.parseInt(req.getAttribute("certType"));
         cert.serverType = Integer.parseInt(req.getAttribute("serverType"));
         cert.lifetime = Integer.parseInt(req.getAttribute("lifetime"));
         cert.numServer = Integer.parseInt(req.getAttribute("numServer"));
      } catch (NumberFormatException e) {
         log.debug("invlaid integer in req");
         throw new CBParseException("bad int");
      }     

      // csr
      Element csrE = XMLHelper.getElementByName(req, "csr");
      cert.pemRequest = csrE.getTextContent();
      log.info("CSR: " + cert.pemRequest);

      // altnames
      Element altnsE = XMLHelper.getElementByName(req, "altNames");
      if (altnsE!=null) {
         List<Element> altnE = XMLHelper.getElementsByName(altnsE, "altName");
         for (int i=0; i<altnE.size(); i++) {
            String an = altnE.get(i).getTextContent();
            cert.formNames.add(an);
            log.debug("form altname  = " + an);
         }
      }

      PEMHelper.parseCsr(cert);
      return cert;
   }
}
