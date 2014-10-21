package edu.washington.iam.ws.cabroker.ca;

import java.io.Serializable;
import java.util.List;

import org.w3c.dom.Document;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.washington.iam.ws.cabroker.registry.CBCertificate;

import edu.washington.iam.ws.cabroker.exception.CertificateAuthorityException;
import edu.washington.iam.ws.cabroker.exception.CBNotFoundException;
import edu.washington.iam.ws.cabroker.exception.NoPermissionException;

public interface CertificateAuthority {

   public int getCertificate(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException ;
   public String getCertificatePKCS7(CBCertificate cert) throws CertificateAuthorityException, CBNotFoundException ;
   public int requestCertificate(CBCertificate cert) throws CertificateAuthorityException,NoPermissionException;
   public int renewCertificate(CBCertificate cert) throws CertificateAuthorityException;
//    public int getRenewStatus(CBCertificate cert);

   public void init();
   public void cleanup();

}
