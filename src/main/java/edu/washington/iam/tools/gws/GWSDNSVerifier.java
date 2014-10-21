/* ========================================================================
 * Copyright (c) 2012 The University of Washington
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


package edu.washington.iam.tools.gws;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;

import edu.washington.iam.tools.DNSVerifier;
import edu.washington.iam.tools.DNSVerifyException;
import edu.washington.iam.tools.WebClient;
import edu.washington.iam.tools.XMLHelper;


public class GWSDNSVerifier implements DNSVerifier {

   private final Logger log =   LoggerFactory.getLogger(getClass());

   private WebClient webClient;
   private String gwsMemberBase = null;

   /**
    * Test if a user has ownership of a domain
    *
    * @param id user's uwnetid
    * @param domain to test
    * @param return list of owners (can be null)
    */

    public boolean isOwner(String dns, String id, List<String> owners) throws DNSVerifyException  {

       boolean isOwner = false;
       if (id==null) id = "";
       log.debug("looking for gws owner (" + id + ") in " + dns);

       try {
          String url = gwsMemberBase + dns + "/effective_member?source=registry";
          Element resp = webClient.doRestGet(url);
          if (resp!=null) {
             Element grpE = XMLHelper.getElementByName(resp, "group");
             Element mbrsE = XMLHelper.getElementByName(grpE, "members");
             List<Element> mbrs = XMLHelper.getElementsByName(mbrsE, "member");
             log.debug("get  " + mbrs.size() + " group members");
             for (int i=0; i<mbrs.size(); i++) {
                String mbr = mbrs.get(i).getTextContent();
                log.debug("mbr: " + mbr);
                if (owners!=null && !owners.contains(mbr)) owners.add(mbr);
                if (mbr.equals(id)) {
                   if (owners==null) return true;
                   isOwner = true;
                }
             }
          }

       } catch (Exception e) {
          log.debug("gws dns lookup error: " + e);
          throw new DNSVerifyException(e.getMessage() + " : " + e.getCause());
       }
       
       // do substrings too
       dns = dns.replaceFirst("[^\\.]+\\.", "");
       // log.debug("do substrings: " + dns);
       int p = dns.indexOf(".");
       if (p>0) {  // only check to the 2nd level
          if (isOwner(dns, id, owners)) {
             if (owners==null) return true;  // done
             isOwner = true;
          }
       }
       return isOwner;
    }

    public boolean isOwner(String dns, String id) throws DNSVerifyException  {
        return isOwner(dns, id, null);
    } 

    public void setWebClient(WebClient v) {
       webClient = v;
    }

    public void setGwsMemberBase(String v) {
       gwsMemberBase = v;
    }


    public void init() {
    }
}
 
