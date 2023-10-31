package edu.washington.iam.ws.cabroker.ca;

import edu.washington.iam.ws.cabroker.exception.CBNotFoundException;
import edu.washington.iam.ws.cabroker.exception.CertificateAuthorityException;
import edu.washington.iam.ws.cabroker.exception.NoPermissionException;
import edu.washington.iam.ws.cabroker.registry.CBCertificate;

public interface CertificateAuthority {

  public int getCertificate(CBCertificate cert)
      throws CertificateAuthorityException, CBNotFoundException;

  public String getCertificatePKCS7(CBCertificate cert)
      throws CertificateAuthorityException, CBNotFoundException;

  public int requestCertificate(CBCertificate cert)
      throws CertificateAuthorityException, NoPermissionException;

  public int renewCertificate(CBCertificate cert) throws CertificateAuthorityException;

  //    public int getRenewStatus(CBCertificate cert);

  public void init();

  public void cleanup();
}
