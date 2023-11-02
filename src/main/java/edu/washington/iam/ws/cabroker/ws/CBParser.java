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

import edu.washington.iam.tools.XMLHelper;
import edu.washington.iam.ws.cabroker.exception.CBParseException;
import edu.washington.iam.ws.cabroker.registry.CBCertificate;
import edu.washington.iam.ws.cabroker.util.PEMHelper;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public final class CBParser {

  private static final Logger log = LoggerFactory.getLogger(CBParser.class);

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
    if (altnsE != null) {
      List<Element> altnE = XMLHelper.getElementsByName(altnsE, "altName");
      for (int i = 0; i < altnE.size(); i++) {
        String an = altnE.get(i).getTextContent();
        cert.formNames.add(an);
        log.debug("form altname  = " + an);
      }
    }

    PEMHelper.parseCsr(cert);
    return cert;
  }
}
