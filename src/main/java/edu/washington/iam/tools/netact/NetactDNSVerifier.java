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


package edu.washington.iam.tools.netact;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.http.client.ResponseHandler;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;
    
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.params.BasicHttpParams;
 
import edu.washington.iam.tools.DNSVerifier;
import edu.washington.iam.tools.DNSVerifyException;
import edu.washington.iam.tools.WebClient;

// google-gson
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;


public class NetactDNSVerifier implements DNSVerifier {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /* Netact rest service provides ownership list */

    private static String hostUrl = null;
    private static String domainUrl = null;
    private WebClient webClient;

    /**
     * Test if a user has ownership of a domain
     *
     * @param id user's uwnetid
     * @param domain to test
     * @param return list of owners (can be null)
     */

    public boolean isOwner(String dns, String id, List<String> owners) throws DNSVerifyException  {
       return _isOwner(true, dns, id, owners);
    }

    private boolean _isOwner(boolean ishost, String dns, String id, List<String> owners) throws DNSVerifyException  {

       boolean isOwner = false;
       if (id==null) id = "";
       log.debug("looking for owner (" + id + ") in " + dns);

       try {
          String url = (ishost? hostUrl:domainUrl) + dns;
          String respString = webClient.simpleRestGet(url);
          log.debug("got: " + respString);

          JsonParser parser = new JsonParser();
          JsonElement ele = parser.parse(respString);
          if (ele.isJsonObject()) {
            JsonObject resp = ele.getAsJsonObject();
            if (resp.get("table").isJsonObject()) {
               JsonObject tbl = resp.getAsJsonObject("table");
               if (tbl.get("row").isJsonArray()) {
                  JsonArray ids = tbl.getAsJsonArray("row");
                  for (int i = 0; i < ids.size(); i++) {
                     JsonObject idi = ids.get(i).getAsJsonObject();
                     JsonPrimitive oidu = idi.getAsJsonPrimitive("uwnetid");
                     if (oidu==null) continue;
                     String oid = oidu.getAsString();
                     if (oid.equals(id)) {
                        if (owners==null) return true;  // done
                        isOwner = true;
                     }
                     if (owners!=null && !owners.contains(oid)) owners.add(oid);
                  }
               } else {
                  String oid = tbl.getAsJsonObject("row").getAsJsonPrimitive("uwnetid").getAsString();
                  if (oid.equals(id)) {
                     if (owners==null) return true;  // done
                     isOwner = true;
                  }
                  if (owners!=null && !owners.contains(oid)) owners.add(oid);
               }
            }
         }

       } catch (Exception e) {
          log.debug("netact dns lookup error: " + e);
          throw new DNSVerifyException(e.getMessage() + " : " + e.getCause());
       }
       
       // do substrings too
       dns = dns.replaceFirst("[^\\.]+\\.", "");
       // log.debug("do substrings: " + dns);
       int p = dns.indexOf(".");
       if (p>0) { 
          if (_isOwner(false, dns, id, owners)) {
             if (owners==null) return true;  // done
             isOwner = true;
          }
       }
       return isOwner;
    }

    public boolean isOwner(String dns, String id) throws DNSVerifyException  {
        return _isOwner(true, dns, id, null);
    } 

    public void setWebClient(WebClient v) {
       webClient = v;
    }
    public void setHostUrl(String v) {
       hostUrl = v;
    }
    public void setDomainUrl(String v) {
       domainUrl = v;
    }

    public void init() {
    }
}
 
