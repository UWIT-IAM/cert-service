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

package edu.washington.iam.ws.cabroker.registry;

import java.util.List;
import java.util.Date;
import java.util.Vector;

/* Certificate broker certificate */

public class CBCertificate {
   public int id;            // my id
   public int ca;           // 1=uw, 2=incommon
   public int caId;         // ca's id
   public String cn;           // CN from cert
   public String dn;           // DN from cert
   public List<String> names;  // cn (1st)  + altnames
   public List<String> formNames;  // altnames from the form
   public String revokePass;
   public String renewId;
   public int status;
   public int certType;
   public int serverType;
   public int lifetime;
   public int numServer;
   public Date issued;
   public Date expires;
   public List<String> owners;   // netids
   public String pemRequest;
   public String pemCert;
   public String remHash;
   public CBRegistry registry;
   public String dnC;   // country code
   public String dnST;  // state 
   public String dnO;   // org 
   public int keySize;
   public List<CBHistory> history;
   public String requestor;
   public String sigAlg;

   public static final String UW_CA_KEY = "uw";
   public static final String IC_CA_KEY = "ic";
   public static final int UW_CA = 1;
   public static final int IC_CA = 2;

   public static final int CERT_STATUS_UNKNOWN = 0;
   public static final int CERT_STATUS_REQUESTED = 1;
   public static final int CERT_STATUS_ISSUED = 2;
   public static final int CERT_STATUS_RENEWING = 3;
   public static final int CERT_STATUS_REVOKED = 4;
   public static final int CERT_STATUS_EXPIRED = 5;
   public static final int CERT_STATUS_DECLINED = 6;
   public static final int CERT_STATUS_GONE = 7;

   public CBCertificate() {
      names = new Vector();
      owners = new Vector();
      formNames = new Vector();
      cn = "";
      dn = "";
      revokePass = "";
      renewId = "";
      expires = null;
      sigAlg = "unknown";
   }

   public int getId() {
      return id;
   }
   public String getCn() {
      return cn;
   }
   public String getDn() {
      return dn;
   }
   public String getCleanDn() {
      if (dn!=null) return dn.replaceAll("<","").replaceAll(">","").replaceAll("&","");
      return null;
   }
  
   public int getCaId() {
      return caId;
   }
   public int getCa() {
      return ca;
   }

   public List<String> getNames() {
      if (names.size()==0) registry.getNames(this);
      return names;
   }

   public List<String> getOwners() {
      if (owners.size()==0) registry.getOwners(this);
      return owners;
   }

   public boolean isOwner(String id) {
      List<String> onrs = getOwners();
      for (int i=0;i<onrs.size();i++) if (id.equals(onrs.get(i))) return true;
      return false;
   }
   public String getCaName() {
      if (ca==1) return "UWCA";
      if (ca==2) return "InCommon";
      return "---";
   }

   public int getStatus() {
      return status;
   }

   public String getStatusText() {
      if (status==0) return "unknown";
      if (status==1) return "requested";
      if (status==2) return "issued";
      if (status==3) return "renewing";
      if (status==4) return "revoked";
      if (status==5) return "expired";
      if (status==6) return "declined";
      if (status==6) return "gone";
      return "unknown";
   }

   public String getPemCert() {
      return pemCert;
   }
   public String getRenewId() {
      return renewId;
   }
   public Date getExpires() {
      return expires;
   }
   public int getKeySize() {
      return keySize;
   }
   public String getSigAlg() {
      return sigAlg;
   }
   public boolean isSha1() {
      if (sigAlg.startsWith("SHA1")) return true;
      return false;
   }


   public void updateDB() {
      registry.updateCertificate(this);
   }

   public List<CBHistory> getHistory() {
      if (history==null) registry.getHistory(this);
      return history;
   }
  
   public int addHistory(int status, Date date, String user) {
      return registry.addHistory(this, status, date, user);
   } 
}

