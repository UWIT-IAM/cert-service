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

import java.io.Serializable;
import java.io.InputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;

import java.util.List;
import java.util.Vector;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.http.entity.StringEntity;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import org.apache.http.client.ResponseHandler;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.entity.UrlEncodedFormEntity;

import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;

import edu.washington.iam.tools.XMLHelper;

public class WebClient {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final ReentrantReadWriteLock locker = new ReentrantReadWriteLock();
    
    // connection params
    private String certFile = null;
    private String keyFile = null;
    private String caFile = null;
    private int queryTimeLimit = 15000;  // fifteen seconds default

    private ClientConnectionManager connectionManager;
    private boolean initialized = false;
    private DocumentBuilder documentBuilder;

    DefaultHttpClient soapclient = null;
    DefaultHttpClient restclient = null;

    HttpParams httpParams = null;

    // 
    private String soapHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + 
        "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " + 
          "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" " + 
          "xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\" " + 
          "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">" +
        "<soap:Body>";
    private String soapTrailer = "</soap:Body></soap:Envelope>";

          // "SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" + 
          // "xmlns:tns=\"http://ssl.ws.epki.comodo.com/\" " +

    public void closeIdleConnections() { 
       // log.debug("closing idle");
       connectionManager.closeExpiredConnections();
       connectionManager.closeIdleConnections(30, TimeUnit.SECONDS);
    }
    
    public Element doSoapRequest(String url, String action, String body) {

       closeIdleConnections();

       // log.debug("do soap: " + action);
       Element ele = null;
       // DefaultHttpClient soapclient = new DefaultHttpClient((ClientConnectionManager)connectionManager, new BasicHttpParams());
       if (soapclient==null) soapclient = new DefaultHttpClient((ClientConnectionManager)connectionManager, new BasicHttpParams());
       // soapclient.getParams().setBooleanParameter(CoreProtocolPNames.USE_EXPECT_CONTINUE, false); 

       try {

          // log.debug(" url: " + url);
          // log.debug("content: [" + soapHeader + body + soapTrailer + "]");

          HttpPost httppost = new HttpPost(url);
          httppost.addHeader("SOAPAction", action);

          StringEntity strent= new StringEntity(soapHeader + body + soapTrailer);
          strent.setContentType("text/xml; charset=utf-8");
          httppost.setEntity(strent); 

          CloseableHttpResponse response = soapclient.execute(httppost);

          if (response.getStatusLine().getStatusCode()>=400) {
              log.error("soap error: "  + response.getStatusLine().getStatusCode() + " = " + response.getStatusLine().getReasonPhrase());
              throw new WebClientException("soap error");
          } 
          HttpEntity entity = response.getEntity();

          // null is error - should get something
          if (entity == null) {
             throw new WebClientException("soapclient post exception");
          }

          // log.debug("got " + entity.getContentLength() + " bytes");
          // parse response text
          Document doc = documentBuilder.parse(entity.getContent());
          
          ele = XMLHelper.getElementByName(doc.getDocumentElement(), "Body");
          if (ele == null) {
             log.error("no body element");
             throw new WebClientException("no body element?");
          }
       } catch (Exception e) {
          log.error("exception " + e);
       }
       return ele;
    }

    public Element doRestGet(String url, String auth) {

       closeIdleConnections();

       // log.debug("do rest get");
       Element ele = null;
       // restclient = new DefaultHttpClient((ClientConnectionManager)connectionManager, new BasicHttpParams());
       if (restclient==null) restclient = new DefaultHttpClient((ClientConnectionManager)connectionManager, new BasicHttpParams());
       try {

          // log.debug(" rest get, url: " + url);
          // log.debug(" auth: " + auth);

          HttpGet httpget = new HttpGet(url);
          if (auth!=null) httpget.addHeader("Authorization", auth);
          httpget.addHeader("Accept", "text/xml");

          CloseableHttpResponse response = restclient.execute((HttpUriRequest)httpget);
          log.debug(" rest get, rsp: " + response.getStatusLine().getStatusCode());
          // httpget.releaseConnection();
          if (response.getStatusLine().getStatusCode()==404) {
              // log.error("rest, url not found");
              response.close();
              return null;
          }
          if (response.getStatusLine().getStatusCode()>=400) {
              // log.error("rest error: "  + response.getStatusLine().getStatusCode() + " = " + response.getStatusLine().getReasonPhrase());
              response.close();
              throw new WebClientException("rest error");
          } 
          HttpEntity entity = response.getEntity();

          // null is error - should get something
          if (entity == null) {
              response.close();
              throw new WebClientException("restclient get exception");
          }

          // parse response text
          Document doc = documentBuilder.parse(entity.getContent());
          ele = doc.getDocumentElement();
          response.close();
       } catch (Exception e) {
          log.error("exception " + e);
       }
       return ele;
    }

    public Element doRestGet(String url) {
       return doRestGet(url, null);
    }

    public Element doRestPut(String url, List<NameValuePair> data, String auth) {

       closeIdleConnections();

       log.debug("do rest put");
       Element ele = null;
       if (restclient==null) restclient = new DefaultHttpClient((ClientConnectionManager)connectionManager, new BasicHttpParams());
       try {

          log.debug(" rest url: " + url);

          HttpPut httpput = new HttpPut(url);
          if (auth!=null) httpput.addHeader("Authorization", auth);
          httpput.setEntity(new UrlEncodedFormEntity(data));

          CloseableHttpResponse response = restclient.execute(httpput);
          log.debug("resp: " + response.getStatusLine().getStatusCode() + " = " + response.getStatusLine().getReasonPhrase());
          HttpEntity entity = response.getEntity();

          // null is error - should get something
          if (entity == null) {
             response.close();
             throw new WebClientException("restclient post exception");
          }

          // parse response text
          Document doc = documentBuilder.parse(entity.getContent());
          ele = doc.getDocumentElement();
          response.close();
       } catch (Exception e) {
          log.error("exception " + e);
       }
       return ele;
    }

   // simple rest get
    public String simpleRestGet(String url)
           throws SocketTimeoutException, WebClientException {

       closeIdleConnections();

       log.debug("simple rest get");
       try {
          HttpParams httpParams = new BasicHttpParams();
          HttpConnectionParams.setConnectionTimeout(httpParams, queryTimeLimit);
          HttpConnectionParams.setSoTimeout(httpParams, queryTimeLimit);
          DefaultHttpClient httpclient = new DefaultHttpClient((ClientConnectionManager)connectionManager, httpParams);

          log.debug(" url: " + url);

          HttpGet httpget = new HttpGet(url);
          HttpResponse response = httpclient.execute(httpget);
          log.debug("resp: " + response.getStatusLine().getStatusCode() + " = " + response.getStatusLine().getReasonPhrase());

          HttpEntity entity = response.getEntity();

          // null is error - should get something
          if (entity == null) {
             throw new WebClientException("httpclient post exception");
          }
          String resp = EntityUtils.toString(entity);
          log.debug(" got: " + resp);
          return (resp);
       } catch (IOException e) {
          log.error("io error " + e.getMessage());
       }
       return null;
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
         if (caFile!=null && certFile!=null && keyFile!=null) {
            log.info("using the socketfactory: ca=" + caFile + ", cert=" + certFile + ", key=" + keyFile);
            IamConnectionManager icm = new IamConnectionManager(caFile, certFile, keyFile);
            connectionManager = icm.getConnectionManager();
/**
         } else {
            log.info("using default socketfactory");
            socketFactory = new SSLSocketFactory();
 **/
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

