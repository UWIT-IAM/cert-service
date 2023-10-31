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

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class WebClient {

  private final Logger log = LoggerFactory.getLogger(getClass());
  private final ReentrantReadWriteLock locker = new ReentrantReadWriteLock();

  // connection params
  private String certFile = null;
  private String keyFile = null;
  private String caFile = null;
  private int queryTimeLimit = 15000; // fifteen seconds default

  private IamConnectionManager iamConnectionManager;
  private boolean initialized = false;
  private DocumentBuilder documentBuilder;

  DefaultHttpClient soapclient = null;
  DefaultHttpClient restclient = null;

  HttpParams httpParams = null; // configured atinit

  //
  private String soapHeader =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
          + "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
          + "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
          + "xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\" "
          + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
          + "<soap:Body>";
  private String soapTrailer = "</soap:Body></soap:Envelope>";

  // "SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
  // "xmlns:tns=\"http://ssl.ws.epki.comodo.com/\" " +

  public void closeIdleConnections() {
    // log.debug("closing idle");
    // connectionManager.closeExpiredConnections();
    // connectionManager.closeIdleConnections(30, TimeUnit.SECONDS);
  }

  private void closeClient(CloseableHttpClient client) {
    try {
      // client.close();
    } catch (Exception e) {
      log.info("close error: " + e.getMessage());
    }
  }

  private void closeResponse(CloseableHttpResponse response) {
    try {
      if (response != null) response.close();
    } catch (Exception e) {
      log.info("close error: " + e.getMessage());
    }
  }

  public Element doSoapRequest(String url, String action, String body) throws WebClientException {

    closeIdleConnections();

    // log.debug("do soap: " + action);
    Element ele = null;
    // DefaultHttpClient soapclient = new
    // DefaultHttpClient((ClientConnectionManager)connectionManager, new BasicHttpParams());
    // if (soapclient==null) soapclient = new
    // DefaultHttpClient((ClientConnectionManager)connectionManager, httpParams);
    // soapclient.getParams().setBooleanParameter(CoreProtocolPNames.USE_EXPECT_CONTINUE, false);

    CloseableHttpClient client = HttpClientBuilder.create().build();
    CloseableHttpResponse response = null;

    try {

      // log.debug(" url: " + url);
      // log.debug("content: [" + soapHeader + body + soapTrailer + "]");

      HttpPost httppost = new HttpPost(url);
      httppost.addHeader("SOAPAction", action);

      StringEntity strent = new StringEntity(soapHeader + body + soapTrailer);
      strent.setContentType("text/xml; charset=utf-8");
      httppost.setEntity(strent);

      // CloseableHttpResponse response = soapclient.execute(httppost);
      response = client.execute(httppost);

      if (response.getStatusLine().getStatusCode() >= 400) {
        log.error(
            "soap error: "
                + response.getStatusLine().getStatusCode()
                + " = "
                + response.getStatusLine().getReasonPhrase());
        closeResponse(response);
        closeClient(client);
        throw new WebClientException("soap error");
      }
      HttpEntity entity = response.getEntity();

      // null is error - should get something
      if (entity == null) {
        closeResponse(response);
        closeClient(client);
        throw new WebClientException("soapclient post exception");
      }

      // log.debug("got " + entity.getContentLength() + " bytes");
      // parse response text
      Document doc = documentBuilder.parse(entity.getContent());

      ele = XMLHelper.getElementByName(doc.getDocumentElement(), "Body");
      if (ele == null) {
        log.error("no body element");
        closeResponse(response);
        closeClient(client);
        throw new WebClientException("no body element?");
      }
      closeResponse(response);
      closeClient(client);
    } catch (IOException e) {
      closeClient(client);
      throw new WebClientException(e.getMessage());
    } catch (Exception e) {
      closeResponse(response);
      closeClient(client);
      throw new WebClientException(e.getMessage());
    }
    closeResponse(response);
    closeClient(client);
    return ele;
  }

  public Element doRestGet(String url, String auth) throws WebClientException {

    closeIdleConnections();

    // log.debug("do rest get");
    Element ele = null;
    // restclient = new DefaultHttpClient((ClientConnectionManager)connectionManager, new
    // BasicHttpParams());
    // if (restclient==null) restclient = new
    // DefaultHttpClient((ClientConnectionManager)connectionManager, httpParams);

    CloseableHttpClient client = iamConnectionManager.getClient();
    CloseableHttpResponse response = null;

    try {

      log.debug(" rest get, url: " + url);

      HttpGet httpget = new HttpGet(url);
      if (auth != null) httpget.addHeader("Authorization", auth);
      httpget.addHeader("Accept", "text/xml");

      response = client.execute((HttpUriRequest) httpget);
      log.debug(" rest get, rsp: " + response.getStatusLine().getStatusCode());
      if (response.getStatusLine().getStatusCode() == 404) {
        // log.error("rest, url not found");
        // closeResponse(response);
        // closeClient(client);
        EntityUtils.consume(response.getEntity());
        return null;
      }
      if (response.getStatusLine().getStatusCode() >= 400) {
        // log.error("rest error: "  + response.getStatusLine().getStatusCode() + " = " +
        // response.getStatusLine().getReasonPhrase());
        // closeResponse(response);
        // closeClient(client);
        EntityUtils.consume(response.getEntity());
        throw new WebClientException("rest error");
      }
      HttpEntity entity = response.getEntity();

      // null is error - should get something
      if (entity == null) {
        closeResponse(response);
        // closeClient(client);
        throw new WebClientException("restclient get exception");
      }

      // parse response text
      Document doc = documentBuilder.parse(entity.getContent());
      ele = doc.getDocumentElement();
      log.debug(" -- consuming response --");
      EntityUtils.consume(response.getEntity());
      // closeResponse(response);
      // closeClient(client);
    } catch (IOException e) {
      closeResponse(response);
      // closeClient(client);
      throw new WebClientException(e.getMessage());
    } catch (SAXException e) {
      closeResponse(response);
      // closeClient(client);
      throw new WebClientException(e.getMessage());
    }
    return ele;
  }

  public Element doRestGet(String url) throws WebClientException {
    return doRestGet(url, null);
  }

  public Element doRestPut(String url, List<NameValuePair> data, String auth)
      throws WebClientException {

    closeIdleConnections();

    log.debug("do rest put");
    Element ele = null;
    // if (restclient==null) restclient = new
    // DefaultHttpClient((ClientConnectionManager)connectionManager, httpParams);

    CloseableHttpClient client = iamConnectionManager.getClient();
    CloseableHttpResponse response = null;

    try {

      log.debug(" rest put url: " + url);

      HttpPut httpput = new HttpPut(url);
      if (auth != null) httpput.addHeader("Authorization", auth);
      httpput.setEntity(new UrlEncodedFormEntity(data));

      response = client.execute(httpput);
      log.debug(
          "resp: "
              + response.getStatusLine().getStatusCode()
              + " = "
              + response.getStatusLine().getReasonPhrase());
      HttpEntity entity = response.getEntity();

      // null is error - should get something
      if (entity == null) {
        closeResponse(response);
        // closeClient(client);
        throw new WebClientException("client post exception");
      }

      // parse response text
      Document doc = documentBuilder.parse(entity.getContent());
      ele = doc.getDocumentElement();
      // closeResponse(response);
      // closeClient(client);
      EntityUtils.consume(response.getEntity());
    } catch (IOException e) {
      closeResponse(response);
      // closeClient(client);
      throw new WebClientException(e.getMessage());
    } catch (SAXException e) {
      closeResponse(response);
      // closeClient(client);
      throw new WebClientException(e.getMessage());
    }
    return ele;
  }

  // simple rest get
  public String simpleRestGet(String url) throws SocketTimeoutException, WebClientException {

    closeIdleConnections();

    log.debug("simple rest get");

    CloseableHttpClient client = iamConnectionManager.getClient();
    CloseableHttpResponse response = null;

    try {
      // log.debug(" url: " + url);

      HttpGet httpget = new HttpGet(url);
      response = client.execute(httpget);
      log.debug(
          "resp: "
              + response.getStatusLine().getStatusCode()
              + " = "
              + response.getStatusLine().getReasonPhrase());

      HttpEntity entity = response.getEntity();

      // null is error - should get something
      if (entity == null) {
        closeResponse(response);
        // closeClient(client);
        throw new WebClientException("client post exception");
      }
      String resp = EntityUtils.toString(entity);
      // closeResponse(response);
      // closeClient(client);
      EntityUtils.consume(response.getEntity());
      return (resp);
    } catch (IOException e) {
      closeResponse(response);
      // closeClient(client);
      throw new WebClientException(e.getMessage());
    } catch (Exception e) {
      closeResponse(response);
      // closeClient(client);
      throw new WebClientException(e.getMessage());
    }
  }

  // initialize

  public void init() {
    log.debug("webclient init");

    // init the doc system
    try {
      DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
      domFactory.setNamespaceAware(false);
      domFactory.setValidating(false);
      String feature = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
      domFactory.setFeature(feature, false);
      documentBuilder = domFactory.newDocumentBuilder();

    } catch (ParserConfigurationException e) {
      log.error("javax.xml.parsers.ParserConfigurationException: " + e);
    }

    // init SSL
    // System.setProperty( "javax.net.debug", "ssl");

    try {
      if (caFile != null && certFile != null && keyFile != null) {
        log.info(
            "using the socketfactory: ca=" + caFile + ", cert=" + certFile + ", key=" + keyFile);
        iamConnectionManager = new IamConnectionManager(caFile, certFile, keyFile);
      }

      httpParams = new BasicHttpParams();
      HttpConnectionParams.setConnectionTimeout(httpParams, queryTimeLimit);
      HttpConnectionParams.setSoTimeout(httpParams, queryTimeLimit);

      initialized = true;

    } catch (Exception e) {
      log.error(" " + e);
    }
    log.debug("gws client initialize done");
  }

  public void setCertFile(String v) {
    certFile = v;
  }

  public void setKeyFile(String v) {
    keyFile = v;
  }

  public void setCaFile(String v) {
    caFile = v;
  }

  public void setQueryTimeLimit(int t) {
    queryTimeLimit = t;
  }
}
