/* ========================================================================
 * Copyright (c) 2009-2011 The University of Washington
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
import java.text.SimpleDateFormat;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import org.springframework.mail.MailException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import edu.washington.iam.ws.cabroker.exception.CertificateManagerException;
import edu.washington.iam.ws.cabroker.exception.NoPermissionException;
import edu.washington.iam.ws.cabroker.exception.CBNotFoundException;
import edu.washington.iam.ws.cabroker.exception.CBParseException;
import edu.washington.iam.ws.cabroker.exception.CertificateAuthorityException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

import java.security.cert.X509Certificate;

import edu.washington.iam.tools.IamCrypt;
import edu.washington.iam.tools.DNSVerifier;
import edu.washington.iam.tools.DNSVerifyException;
import edu.washington.iam.ws.cabroker.ca.CertificateAuthority;
import edu.washington.iam.ws.cabroker.registry.CBCertificate;
import edu.washington.iam.ws.cabroker.registry.CBRegistry;
import edu.washington.iam.ws.cabroker.registry.CBHistory;


@Controller
public class CBController {

    private final Logger log =  LoggerFactory.getLogger(getClass());

    private static CBRegistry cbRegistry;
    private static CertificateAuthority uwCA;
    private static CertificateAuthority icCA;
    public static CertificateAuthority getCA(int ca) {
       if (ca==1) return uwCA;
       if (ca==2) return icCA;
       return null;
    }
    private static DNSVerifier dnsVerifier;

    // messaging from here not used yet
    private MailSender mailSender;
    private SimpleMailMessage csMessage;

    public void setMailSender(MailSender mailSender) {
       this.mailSender = mailSender;
    }

    public void setTemplateMessage(SimpleMailMessage csMessage) {
       this.csMessage = csMessage;
    }

    private static String browserRootPath;
    private static String certRootPath;
    private static String loginCookie;
    private static String logoutUrl;
    private static String errorUrl;

    private static String mailTo = "fox@u.washington.edu";
    private static String requestMailTo = "fox@u.washington.edu";

    // sessions
    private String standardLoginPath = "/login";
    private String standardDSLoginPath = "/dslogin";
    private String secureLoginPath = "/securelogin";
    private long standardLoginSec = 9*60*60;  // 9 hour session lifetime
    private long secureLoginSec = 1*60*60;  // 1 hour session lifetime

    private String myEntityId = null;
    private String eppnName = "eppn";  // env var name of user eppn
    
    // key for crypt ops
    private static String cryptKey;

    class CBSession {
       private String viewType;
       private String remoteUser;
       private String rootPath;
       private String servletPath;
       private String pageType;
       private String pageTitle;
       private long ifMatch;
       private long ifNoneMatch;
       private String errorCode;
       private String errorText;
       private boolean isBrowser;
       private String xsrfCode;
       private String remoteAddr;
       private String loginMethod;
       private boolean authn2;
       private boolean isUWLogin;
       private String userIdProvider;
       private String userDisplayName;
       private long timeLeft;
    }

    private CBSession processRequestInfo(HttpServletRequest request, HttpServletResponse response, boolean canLogin) {
        CBSession session = new CBSession();
        session.authn2 = false;
        session.isUWLogin = false;

        log.info("CB new session =============== path=" + request.getPathInfo());

        // see if logged in (browser has login cookie; cert user has cert)

        Cookie[] cookies = request.getCookies();
        if (cookies!=null) {
          for (int i=0; i<cookies.length; i++) {
            if (cookies[i].getName().equals(loginCookie)) {
               log.debug("got cookie " + cookies[i].getName());
               String cookieStr = IamCrypt.decode(cookies[i].getValue());
               String[] cookieData = cookieStr.split(";");

               if (cookieData.length==5) {

                  if (cookieData[3].charAt(0)=='2') session.authn2 = true;

                  log.debug("login time = " + cookieData[4]);
                  long cSec = new Long(cookieData[4]);
                  long nSec = new Date().getTime()/1000;
                  if (cookieData[1].indexOf("@")<0) session.isUWLogin = true;  // klugey way to know UW people
                  session.timeLeft = (cSec+standardLoginSec) - nSec;

                  if (session.timeLeft>0) {
                     if ((nSec>(cSec+secureLoginSec)) && session.authn2) {
                        log.debug("secure expired");
                        session.authn2 = false;
                     }

                     // cookie OK
                     session.remoteUser = cookieData[1];
                     session.xsrfCode = cookieData[2];
                     log.debug("login for " + session.remoteUser );
                     if (session.authn2) log.debug("secure login");
                     break;
                  } else log.debug("cookie expired for " + cookieData[1]);
               } else {
                  log.info("bogus cookie ignored");
               }
            }
          }
        }


        if (session.remoteUser!=null) {
           // ok, is a logged in browser
           session.viewType = "browser";
           session.isBrowser = true;
           session.rootPath = browserRootPath;

        } else {
           // maybe is cert client
           // use the CN portion of the DN as the client userid
           X509Certificate[] certs = (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
           if (certs != null) {
             session.viewType = "plain";
             session.isBrowser = false;
             session.rootPath = certRootPath;
             X509Certificate cert = certs[0];
             String dn = cert.getSubjectX500Principal().getName();
             session.remoteUser = dn.replaceAll(".*CN=", "").replaceAll(",.*","");
             log.info(".. remote user by cert, dn=" + dn + ", cn=" + session.remoteUser);
           }

        }

        /* send missing remoteUser to login */

        if (session.remoteUser==null) {
           if (canLogin) {
              if (session.isUWLogin) sendToLogin(request, response, standardLoginPath);
              else sendToLogin(request, response, standardDSLoginPath);
           }
           return null;
        }

        session.servletPath = request.getServletPath();
        session.remoteAddr = request.getRemoteAddr();

        // etag headers
        session.ifMatch = getLongHeader(request, "If-Match");
        session.ifNoneMatch = getLongHeader(request, "If-None-Match");
        // log.info("tags: match=" + session.ifMatch + ", nonematch=" + session.ifNoneMatch);

        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max_age=1");
        response.setHeader("X-UA-Compatible", "IE=7");

        log.info("user: " + session.remoteUser);
        return session;
    }

    private String fixPathName(String start, HttpServletRequest request) {
       String path = request.getPathInfo();
       // log.debug("full path = " + path);
       path = path.substring(start.length());
       // log.debug("trunc path = " + path);
       int slash = path.indexOf("/");
       if (slash>0) path = path.substring(0, slash);
       // log.debug("fixed path = " + path);
       return path;
    }

    /* send user to login page */
    private void sendToLogin(HttpServletRequest request, HttpServletResponse response, String loginPath) {

       // delete any existing sessions first
       Cookie[] cookies = request.getCookies();
       if (cookies!=null) {
         for (int i=0; i<cookies.length; i++) {
           if (cookies[i].getName().startsWith("_shib")) {
              log.debug("clearing cookie " + cookies[i].getName());
              Cookie c = new Cookie(cookies[i].getName(), "");
              c.setSecure(true);
              c.setPath("/");
              c.setMaxAge(0);
              response.addCookie(c);
           }
         }
       }
    
       String rp = "";
       if (request.getPathInfo()!=null) rp = request.getPathInfo();
       String rqs = "";
       if (request.getQueryString()!=null) rqs = "?" +  request.getQueryString();
       String red = browserRootPath + request.getServletPath() + loginPath + rp + rqs;
       log.debug("no user yet: redirect for login to " + red);
       try {
          response.sendRedirect(red);
       } catch (IOException e) {
          log.error("redirect: " + e);
       }
    }

    // create basic model and view
    private ModelAndView basicModelAndView(CBSession session, String view, String basePage) {
        ModelAndView mv = new ModelAndView(view + "/" + basePage);
        log.debug("view: " + view + "/" + basePage);
        mv.addObject("remote_user", session.remoteUser);
        mv.addObject("root", session.rootPath);
        mv.addObject("vers", session.servletPath);
        if (session.pageType != null) mv.addObject("pageType", view + "/" + session.pageType);
        mv.addObject("pageTitle", session.pageTitle);
        mv.addObject("xsrf", session.xsrfCode);
        mv.addObject("timeLeft", session.timeLeft);
        return mv;
    }
    private ModelAndView basicModelAndView(CBSession session) {
        return (basicModelAndView(session, session.viewType, "page"));
    }
    private ModelAndView basicModelAndView(CBSession session, String view) {
        return (basicModelAndView(session, view, "page"));
    }

    // create 'empty' model and view
    private ModelAndView emptyMV(String message, String alert) {
        ModelAndView mv = new ModelAndView("empty");
        if (message!=null) mv.addObject("msg", message);
        if (message!=null) mv.addObject("alert", alert);
        return mv;
    }
    private ModelAndView emptyMV(String msg) {
        return emptyMV(msg, null);
    }
    private ModelAndView emptyMV() {
        return emptyMV("session error");
    }

    /*
     * Process login page.
     * Set a cookie and redirect back to original request
     * Encode remoteuser, method and time into the login cookie
     * Bug is shib(?) causes Shib-AuthnContext-Class to sometimes be invalid, so get method from the location
     */

    private ModelAndView loginPage(HttpServletRequest request, HttpServletResponse response, int method) {
       String methodKey = "P";
       if (method==2) methodKey = "2";
       log.debug("method = " + method + ", key = " + methodKey);

       // we need some shib attrs
       String remoteUser = (String)request.getAttribute(eppnName);
       String provider = (String)request.getAttribute("Shib-Identity-Provider");
       log.debug("eppn("+eppnName+")=" + remoteUser + " rus=" + request.getRemoteUser() + " prov=" + provider + " m=" + method + " k=" + methodKey);
       if (remoteUser!=null) {
           if (remoteUser.endsWith("@washington.edu")) {
              remoteUser = remoteUser.substring(0, remoteUser.lastIndexOf("@washington.edu"));
              log.info("dropped @washington.edu to get id = " + remoteUser);
           }
           double dbl = Math.random();
           long modtime = new Date().getTime();  // milliseconds
           log.debug("login: ck = ...;" + remoteUser + ";" + dbl + ";" + methodKey + ";" + modtime/1000);
           String enc = IamCrypt.encode(Double.toString(modtime)+ ";" + remoteUser + ";" + dbl + ";" + methodKey + ";" + modtime/1000);
           log.debug("login: enc = " + enc);
           Cookie c = new Cookie(loginCookie, enc);
           c.setSecure(true);
           c.setPath("/");
           response.addCookie(c);
           try {
              String rp = request.getPathInfo();
              int sp = rp.indexOf("/", 2);
              log.debug("in path = " +  rp);
              String red = browserRootPath + request.getServletPath();
              if (sp>1) red = red + rp.substring(sp);
              if (request.getQueryString()!=null)  red = red + "?" + request.getQueryString();
              log.debug("logon ok, return to " + red);
              response.sendRedirect(red);
           } catch (IOException e) {
              log.error("redirect: " + e);
              return emptyMV("redirect error");
           }
       } else {
           // send login failed message
           ModelAndView mv = new ModelAndView("browser/page");
           mv.addObject("root", browserRootPath);
           mv.addObject("vers", request.getServletPath());
           mv.addObject("pageType", "browser/nologin");
           mv.addObject("pageTitle", "login failed");
           mv.addObject("myEntityId", myEntityId);
           mv.addObject("provider", provider);
           return mv;
       }
       return emptyMV();
    }

    @RequestMapping(value="/login/**", method=RequestMethod.GET)
    public ModelAndView basicLoginPage(HttpServletRequest request, HttpServletResponse response) {
        return loginPage(request, response, 1);
    }

    @RequestMapping(value="/dslogin/**", method=RequestMethod.GET)
    public ModelAndView dsLoginPage(HttpServletRequest request, HttpServletResponse response) {
        return loginPage(request, response, 1);
    }

    @RequestMapping(value="/securelogin/**", method=RequestMethod.GET)
    public ModelAndView secureLoginPage(HttpServletRequest request, HttpServletResponse response) {
        return loginPage(request, response, 2);
    }

    /*
     * Process logoutt page
     * Clear cookies, redirect to shib logout
     */

    @RequestMapping(value="/logout/**", method=RequestMethod.GET)
    public ModelAndView logoutPage(HttpServletRequest request, HttpServletResponse response) {
        // clear cookies
        Cookie[] cookies = request.getCookies();
        if (cookies!=null) {
          for (int i=0; i<cookies.length; i++) {
            String ckName = cookies[i].getName();
            if (ckName.equals(loginCookie) || ckName.startsWith("_shib")) {
               log.debug("cookie to clear " + ckName);
               Cookie c = new Cookie(ckName, "void");
               c.setSecure(true);
               c.setPath("/");
               c.setMaxAge(0);
               response.addCookie(c);
            }
          }
        }
        try {
           log.debug("redirect to: " +  logoutUrl);
           response.sendRedirect(logoutUrl);
        } catch (IOException e) {
           log.error("redirect: " + e);
        }
        return emptyMV("configuration error");
    }


    // show main page
    @RequestMapping(value="/", method=RequestMethod.GET)
    public ModelAndView homePage(HttpServletRequest request, HttpServletResponse response) {

        CBSession session = processRequestInfo(request, response, true);
        if (session==null) return (emptyMV());
        log.info("/ view");
        log.info(".. path=" + request.getPathInfo());

        session.pageTitle = "Certificate service home";
        session.pageType = "home";

        ModelAndView mv = basicModelAndView(session);

        return (mv);
    }

    // home pages (if 'v1' alone)
    @RequestMapping(value="/v1", method=RequestMethod.GET)
    public ModelAndView homePageV1(HttpServletRequest request, HttpServletResponse response) {
        log.info("v1 view");
        return homePage(request, response);
    }


    // wants new request page
    @RequestMapping(value="/req", method=RequestMethod.GET)
    public ModelAndView newRequest(@RequestParam(value="innerview", required=false) String optInnerview,
           @RequestParam(value="type", required=false) String optType,
           HttpServletRequest request, HttpServletResponse response) {

        boolean innerView = false;
        if (optInnerview!=null && optInnerview.equals("yes")) innerView = true;
        

        CBSession session = processRequestInfo(request, response, !innerView);
        if (session==null) {
           if (innerView) response.setStatus(402);
           return emptyMV();
        }
        log.info("want new request page");

        session.pageTitle = "New request";
        session.pageType = "new_ic";
        if (optType!=null && optType.equals("uw")) session.pageType = "new_uw";
        if (optType!=null && optType.equals("ver")) session.pageType = "verify";

        ModelAndView mv = null;
        if (innerView) mv = basicModelAndView(session, session.viewType, session.pageType);
        else mv = basicModelAndView(session);

        mv.addObject("title","Certificate Request");

        return (mv);
    }


    // find certs page
    @RequestMapping(value="/search", method=RequestMethod.GET)
    public ModelAndView search(@RequestParam(value="owner", required=false) String optOwn,
            @RequestParam(value="name", required=false) String optName,
            @RequestParam(value="seluw", required=false) String optUW,
            @RequestParam(value="selic", required=false) String optIC,
            @RequestParam(value="innerview", required=false) String optInnerview,
            HttpServletRequest request, HttpServletResponse response) {

        boolean innerView = false;
        if (optInnerview!=null && optInnerview.equals("yes")) innerView = true;

        CBSession session = processRequestInfo(request, response, !innerView);
        if (session==null) {
           if (innerView) response.setStatus(402);
           return emptyMV();
        }

        session.pageType = "certs";
        session.pageTitle = "certificates" ;

        List<CBCertificate> certs;

        String selOwn = cleanString(optOwn);
        String selName = cleanString(optName);

        boolean selUW = true;
        if (optUW!=null && optUW.startsWith("n")) selUW = false;
        boolean selIC = true;
        if (optIC!=null && optIC.startsWith("n")) selIC = false;
        if (!(selUW||selIC)) {  // deal with nonsenical params
           selUW = true;
           selIC = true;
        }

        int idno = 0;
        try {
            idno = Integer.parseInt(selName);
        } catch (NumberFormatException e) {
            idno = 0;
        }
        certs = cbRegistry.getCertificates(idno, selOwn, selName, selUW, selIC);
 
        ModelAndView mv = null;
        if (innerView) mv = basicModelAndView(session, session.viewType, session.pageType);
        else mv = basicModelAndView(session);

        if (selOwn==null && selName==null) mv.addObject("title", "My Certificates");
        else if (selOwn!=null) mv.addObject("title", "Certificates owned by " + selOwn);
        else mv.addObject("title", "Certificates matching '" + selName + "'");
        mv.addObject("selowner", selOwn);
        mv.addObject("selname", selName);
        mv.addObject("seluw", selUW);
        mv.addObject("selic", selIC);
        mv.addObject("certs", certs);
        mv.addObject("dateFormatter", new SimpleDateFormat("yyyy/MM/dd"));

        return (mv);
    }

    // specific cert
    @RequestMapping(value="/cert", method=RequestMethod.GET)
    public ModelAndView getCert(@RequestParam(value="id", required=true) Integer id,
            @RequestParam(value="ca", required=false) String paramCa,
            @RequestParam(value="caid", required=false) Integer paramCaId,
            @RequestParam(value="innerview", required=false) String paramInnerview,
            HttpServletRequest request,
            HttpServletResponse response) {

        boolean innerView = false;
        if (paramInnerview!=null && paramInnerview.equals("yes")) innerView = true;

        CBSession session = processRequestInfo(request, response, !innerView);
        if (session==null) {
           if (innerView) response.setStatus(402);
           return emptyMV();
        }

        log.debug("REQ: get cert " + id);
        session.pageType = "cert";
        session.pageTitle = "Certificate";

        CBCertificate cert = null;

        String errmsg = null;
        int ca = cbRegistry.getCaFromString(paramCa);

        try {
           if (ca>=0) {
              id = cbRegistry.getCertificateId(ca, paramCaId);
              if (id>0) {
                 cert = cbRegistry.getCertificate(id);
              } else {
                 log.debug("importing " + paramCaId + " from " + paramCa);
                 cert = new CBCertificate();
                 cert.ca = ca;
                 cert.caId = paramCaId;
                 cert.status = 0;
                 cert.registry = cbRegistry;
              }
           } else {
              cert = cbRegistry.getCertificate(id);
           }
           if (cert.status!=CBCertificate.CERT_STATUS_REVOKED && cert.status!=CBCertificate.CERT_STATUS_DECLINED) {
              log.debug("getting the cert from the ca");
              if (cert.ca==CBCertificate.IC_CA) icCA.getCertificate(cert);
              else uwCA.getCertificate(cert);
              // if (cert.id==0 || cert.status==CBCertificate.CERT_STATUS_REVOKED ||
              //         cert.status==CBCertificate.CERT_STATUS_EXPIRED) cbRegistry.putCertificate(cert);
           }
        } catch (CertificateAuthorityException e) {
           return emptyMV(e.getMessage());
        } catch (CBNotFoundException e) {
           log.debug("cert is no more");
           ModelAndView mv = basicModelAndView(session, session.viewType, "certgone");
           mv.addObject("id", id);
           return (mv);
        }

        log.info("returning cert id=" + id );

        ModelAndView mv = null;
        if (innerView) mv = basicModelAndView(session, session.viewType, session.pageType);
        else mv = basicModelAndView(session);

        mv.addObject("title","Certificate: " + cert.cn);
        mv.addObject("cert", cert);
        mv.addObject("dateFormatter", new SimpleDateFormat("MM/dd/yyyy HH:mm:ss"));

        // add days till expire
        if ((cert.status==CBCertificate.CERT_STATUS_ISSUED||cert.status==CBCertificate.CERT_STATUS_EXPIRED) && cert.getExpires()!=null) {
           long nowsec = new Date().getTime()/1000;
           long expdays = (cert.getExpires().getTime()/1000 - nowsec) / (24*3600);
           log.debug("exp in " + expdays + " days");
           mv.addObject("expdays", expdays);
        }

        return (mv); 
    }

    // cert text as pkcs7

    @RequestMapping(value="/pkcs7/{name}", method=RequestMethod.GET)
    public ModelAndView getPkcs7(@PathVariable("name") String certName,
            @RequestParam(value="id", required=true) Integer id,
            HttpServletRequest request,
            HttpServletResponse response) {

        log.debug("REQ: get pkcs7 " + id);

        ModelAndView mv = new ModelAndView("pkcs7");

        CBCertificate cert = null;

        try {
           cert = cbRegistry.getCertificate(id);
           log.debug("ws getting the cert");
           String pkcs7 = "";
           if (cert.ca==CBCertificate.UW_CA) pkcs7 = uwCA.getCertificatePKCS7(cert);
           else pkcs7 = icCA.getCertificatePKCS7(cert);
           mv.addObject("pkcs7", pkcs7);
           response.setContentType("application/octet-stream");
        } catch (CertificateAuthorityException e) {
           response.setStatus(400);
        } catch (CBNotFoundException e) {
           response.setStatus(404);
        }

        return (mv); 
    }

    // submit new cert request
    @RequestMapping(value="/req", method=RequestMethod.PUT)
    public ModelAndView putNewRequest(InputStream in,
            HttpServletRequest request,
            HttpServletResponse response) {

        CBSession session = processRequestInfo(request, response, true);
        if (session==null) return (emptyMV());
        log.info("PUT new request");
        int status = 200;

        ModelAndView mv = basicModelAndView(session, "innerhtml", "new");

        Document doc = null;
        try {
            DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = builderFactory.newDocumentBuilder();
            doc = builder.parse (in);
        } catch (Exception e) {
            log.info("parse error: " + e);
            status = 400;
            mv.addObject("alert", "The posted document was not valid:\n" + e);
            response.setStatus(status);
            return mv;
        }

        try {
           CBCertificate cert = CBParser.parseRequest(doc);
           log.debug("have req for " + cert.ca);
 
           // do some quick validation
           if (!cert.dnC.equals("US")) throw new CBParseException("Country must be 'US'");
           if (!(cert.dnST.equals("WA")||cert.dnST.equals("Washington"))) throw new CBParseException("State must be 'WA' or 'Washington'");
           if (!cert.dnO.equals("University of Washington")) throw new CBParseException("Organization must be 'University of Washington'");
           if (cert.lifetime > 24 && cert.ca==CBCertificate.IC_CA) throw new CBParseException("Lifetime must be 24 months or fewer.");
           if (cert.keySize>0 && cert.keySize<2048 &&
               cert.ca==CBCertificate.IC_CA) throw new CBParseException("Key length must be 2048");
           verifyOwnership(cert, session.remoteUser);
           cert.requestor = session.remoteUser;

           if (cert.ca==CBCertificate.IC_CA) icCA.requestCertificate(cert);
           else if (cert.ca==CBCertificate.UW_CA) uwCA.requestCertificate(cert);

           cbRegistry.putCertificate(cert);
           cbRegistry.addHistory(cert, CBHistory.CB_HIST_REQ, new Date(), session.remoteUser);
           mv.addObject("cert", cert);

        } catch (DNSVerifyException e) {
           status = 203;
           mv.addObject("alert", formatError("Could not verify DNS ownership", e));
        } catch (NoPermissionException e) {
           status = 203;
           mv.addObject("alert", formatError("You do not have permission", e));
        } catch (CertificateManagerException e) {
           log.debug(" cm failed: " + e);
           status = 203;
           mv.addObject("alert", formatError("Certificate manager reports exception", e));
        } catch (CertificateAuthorityException e) {
           log.debug(" ca failed: " + e);
           status = 203;
           mv.addObject("alert", formatError("The CA reports exception", e));
        } catch (CBParseException e) {
           log.debug(" invalid");
           status = 203;
           mv.addObject("alert", formatError("Invalid Request", e));
        }

        response.setStatus(status);
        return mv;
    }

    // submit renew request

    @RequestMapping(value="/renew", method=RequestMethod.PUT)
    public ModelAndView putRenewRequest(@RequestParam(value="id", required=true) Integer id,
               HttpServletResponse response,
               HttpServletRequest request) {

        CBSession session = processRequestInfo(request, response, false);
        if (session==null) return (emptyMV());

        log.info("REQ: renew: " + id );

        int status = 200;

        ModelAndView mv = basicModelAndView(session, "innerhtml", "renew");

        CBCertificate cert = null;

        String errmsg = null;
        try {
           cert = cbRegistry.getCertificate(id);
           verifyOwnership(cert, session.remoteUser);
           if (cert.status!=CBCertificate.CERT_STATUS_REVOKED) {
              log.debug("asking for renew from the ca");
              if (cert.ca==CBCertificate.IC_CA) icCA.renewCertificate(cert);
              else uwCA.renewCertificate(cert);
              if (cert.status==CBCertificate.CERT_STATUS_RENEWING) {
                 cbRegistry.updateCertificate(cert);
                 cbRegistry.addHistory(cert, CBHistory.CB_HIST_REN, new Date(), session.remoteUser);
              } else {
                 status = 500;
                 mv.addObject("alert", "renew failed");
              }
           }
           mv.addObject("cert", cert);
        } catch (CertificateAuthorityException e) {
           status = 203;
           mv.addObject("alert", formatError("The CA reports exception", e));
        } catch (CBNotFoundException e) {
           status = 203;
           mv.addObject("alert", formatError("The certificate was not found", e));
        } catch (DNSVerifyException e) {
           status = 203;
           mv.addObject("alert", formatError("Could not verify DNS ownership", e));
        } catch (NoPermissionException e) {
           status = 203;
           mv.addObject("alert", formatError("You do not have permission", e));
        }

        response.setStatus(status);
        return mv;
    }

    // ajax search page
    @RequestMapping(value="/ajaxSearch", method=RequestMethod.GET)
    public ModelAndView ajaxSearch(@RequestParam(value="owner", required=false) String optOwn,
            @RequestParam(value="name", required=false) String optName,
            @RequestParam(value="seluw", required=false) String optUW,
            @RequestParam(value="selic", required=false) String optIC,
            HttpServletRequest request, HttpServletResponse response) {

        CBSession session = processRequestInfo(request, response, false);
        if (session==null) return (emptyMV());

        session.pageType = "innerhtml/certs";
        session.pageTitle = "ajax certificates" ;

        List<CBCertificate> certs = null;

        String selOwn = cleanString(optOwn);
        String selName = cleanString(optName);

        boolean selUW = true;
        if (optUW!=null && optUW.startsWith("n")) selUW = false;
        boolean selIC = true;
        if (optIC!=null && optIC.startsWith("n")) selIC = false;
        if (!(selUW||selIC)) {  // deal with nonsenical params
           selUW = true;
           selIC = true;
        }

        if (selName!=null) {  // see if num
           try {
              int no = Integer.parseInt(selName);
              certs = cbRegistry.getCertificates(no, null, null, true, true);
           } catch (NumberFormatException e) {
           }
        }
        if (certs==null) certs = cbRegistry.getCertificates(selOwn, selName, selUW, selIC);
 
        ModelAndView mv = basicModelAndView(session, "innerhtml", "certs");
        mv.addObject("certs", certs);
        // mv.addObject("dateFormatter", new SimpleDateFormat("yyyy/MM/dd HH:mm:ss"));
        mv.addObject("dateFormatter", new SimpleDateFormat("yyyy/MM/dd"));
        response.setHeader("Content-type", "text/xml");

        return (mv);
    }

    // ajax cert timestamp page
    @RequestMapping(value="/ajaxTs", method=RequestMethod.GET)
    public ModelAndView ajaxSearch(HttpServletRequest request, HttpServletResponse response) {

        CBSession session = processRequestInfo(request, response, false);
        if (session==null) return (emptyMV());

        session.pageType = "json/ts";
        session.pageTitle = "ajax ts" ;

        long ts = cbRegistry.getCertificateTS();
 
        ModelAndView mv = basicModelAndView(session, "json", "ts");
        mv.addObject("ts", ts);
        response.setHeader("Content-type", "application/json");

        return (mv);
    }

    // test if user is owner of domain

    @RequestMapping(value="/ajax/verify", method=RequestMethod.GET)
    public ModelAndView ajaxMember(@RequestParam(value="dns", required=true) String paramDns,
            @RequestParam(value="id", required=false) String optId,
            HttpServletResponse response,
            HttpServletRequest request) {

        int status = 404;
        CBSession session = processRequestInfo(request, response, false);
        if (session==null) return (emptyMV());

        log.info("REQ: ajax test dns: " + paramDns );

        session.pageType = "innerhtml/dns";
        ModelAndView mv = basicModelAndView(session, "innerhtml", "dns");

        String dns = cleanString(paramDns);
        mv.addObject("dns", dns);
        String tid = session.remoteUser;
        if (optId!=null) {
           tid = cleanString(optId);
           mv.addObject("id", tid);
        }
        try {
           if (dnsVerifier.isOwner(dns, tid, null) ) status = 200; // not found
        } catch (DNSVerifyException e) {
           mv.addObject("alert", "Could not verify ownership:\n" + e.getCause());
           response.setStatus(500);
           return mv;
        }
        response.setStatus(status);
        return mv;
    }

    // add user to owners

    @RequestMapping(value="/ajax/owner", method=RequestMethod.PUT)
    public ModelAndView ajaxOwnerAdd(@RequestParam(value="id", required=true) Integer id,
               HttpServletResponse response,
               HttpServletRequest request) {

        CBSession session = processRequestInfo(request, response, false);
        if (session==null) return (emptyMV());

        log.info("REQ: ajax add owner: " + id );

        session.pageType = "innerhtml/owner";
        response.setStatus(cbRegistry.addOwner(id, session.remoteUser));
        return emptyMV();
    }

    // drop user to owners

    @RequestMapping(value="/ajax/owner", method=RequestMethod.DELETE)
    public ModelAndView ajaxOwnerDel(@RequestParam(value="id", required=true) Integer id,
               HttpServletResponse response,
               HttpServletRequest request) {

        CBSession session = processRequestInfo(request, response, false);
        if (session==null) return (emptyMV());

        log.info("REQ: ajax delete owner: " + id );

        session.pageType = "innerhtml/owner";
        response.setStatus(cbRegistry.deleteOwner(id, session.remoteUser));
        return emptyMV();
    }

    public void setUwCertificateAuthority(CertificateAuthority m) {
        uwCA = m;
    }

    public void setIcCertificateAuthority(CertificateAuthority m) {
        icCA = m;
    }

    public void setDnsVerifier(DNSVerifier v) {
        dnsVerifier = v;
    }

    public void setCbRegistry(CBRegistry v) {
        cbRegistry = v;
    }

    public static CBRegistry getCBRegistry() {
       return cbRegistry;
    }

    /* utility */
    

    private long getLongHeader(HttpServletRequest request, String name) {
       try {
          String hdr = request.getHeader(name);
          if (hdr==null) return 0;
          if (hdr.equals("*")) return (-1);
          return Long.parseLong(hdr);
       } catch (NumberFormatException e) {
          return 0;
       }
    }
    private String cleanString(String in) {
       if (in==null) return null;
       return in.replaceAll("&", "").replaceAll("<", "").replaceAll(">", "");
    }
    public void setCertRootPath(String path) {
        certRootPath = path;
    }
    public void setBrowserRootPath(String path) {
        browserRootPath = path;
    }

    public void setLoginCookie(String v) {
        loginCookie = v;
    }

    public void setLogoutUrl(String v) {
        logoutUrl = v;
    }

    public void setErrorUrl(String v) {
        errorUrl = v;
    }

    public void setCryptKey(String v) {
        cryptKey = v;
    }

    public void setMailTo(String v) {
        mailTo = v;
    }
    public void setRequestMailTo(String v) {
        requestMailTo = v;
    }

    public void setStandardLoginSec(long v) {
        standardLoginSec = v;
    }
    public void setSecureLoginSec(long v) {
        secureLoginSec = v;
    }

    public void setStandardLoginPath(String v) {
        standardLoginPath = v;
    }
    public void setSecureLoginPath(String v) {
        secureLoginPath = v;
    }
    public void setStandardDSLoginPath(String v) {
        standardDSLoginPath = v;
    }

    public void setEppnName(String v) {
        eppnName = v;
    }
    public void setMyEntityId(String v) {
        myEntityId = v;
    }

    /* 
     * Verify ownership of all the names requested
     */

    private void verifyOwnership(CBCertificate cert, String user) throws NoPermissionException, DNSVerifyException {
       boolean wc = false;
       for (int i=0; i<cert.names.size(); i++) {
          String cn = cert.names.get(i);
          if (cn.startsWith("*.")) {
             wc = true;
             cn = cn.substring(2);
          }
          if (cn.indexOf("*")>=0) throw new NoPermissionException("invalid wildcard.");
          if (!cn.matches("([\\w]+[\\w\\-]*\\.)+[a-z]+")) throw new DNSVerifyException("CN or altName not valid.");
          if (!dnsVerifier.isOwner(cn, user, i==0?cert.owners:null)) {
             log.debug("user " + user + " not owner of " + cn);
             throw new NoPermissionException("You are not an owner of " + cn + ".");
          }
       }
       // also check any form altnames
       for (int i=0; i<cert.formNames.size(); i++) {
          String cn = cert.formNames.get(i);
          if (cn.startsWith("*.")) {
             wc = true;
             cn = cn.substring(2);
          }
          if (cn.indexOf("*")>=0) throw new NoPermissionException("invalid wildcard.");
          if (!cn.matches("([\\w]+[\\w\\-]*\\.)+[a-z]+")) throw new DNSVerifyException("CN or altName not valid.");
          if (!dnsVerifier.isOwner(cn, user, null)) {
             log.debug("user " + user + " not owner of " + cn);
             throw new NoPermissionException("You are not an owner of " + cn + ".");
          }
       }
    }

    /* format an error response */

    private String formatError(String msg, Exception e) {
       return "<span align=\"center\"><h4>" + msg + "</h4><p>" + e.getMessage() + "<p>See <a href=\"" +
               errorUrl + "\" target=\"_blank\">Certificate Service Errors</a> for details and solutions.</span>";
    }


    /* See if extra login suggested.
     */
/**
    private boolean needMoreAuthn(GwsGroup group, GwsSession session, HttpServletResponse response) {
       if (group.getSecurityLevel()>1 && !session.authn2) {
           log.debug("update needs 2-factor");
           if (session.isBrowser) response.setStatus(402);
           else response.setStatus(401);
           return true;
       }
       return false;
    }
 **/

    public void init() {
       log.info("CBController init");
       IamCrypt.init(cryptKey);
    }

    // diagnostic
    @RequestMapping(value="/**", method=RequestMethod.GET)
    public ModelAndView homePageStar(HttpServletRequest request, HttpServletResponse response) {
        log.info("Star view");
        return homePage(request, response);
    }

}
