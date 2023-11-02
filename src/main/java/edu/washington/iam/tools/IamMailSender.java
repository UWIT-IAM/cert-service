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

package edu.washington.iam.tools;

import com.sun.mail.smtp.SMTPAddressFailedException;
import com.sun.mail.smtp.SMTPSenderFailedException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import javax.mail.Address;
import javax.mail.Message.RecipientType;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.javamail.JavaMailSenderImpl;

// local interface to java mail sender

public class IamMailSender {

  private final Logger log = LoggerFactory.getLogger(getClass());

  private boolean active = true;

  public void setActive(boolean a) {
    this.active = a;
  }

  private JavaMailSenderImpl mailSender;

  public void setMailSender(JavaMailSenderImpl mailSender) {
    this.mailSender = mailSender;
  }

  private String replyTo = "iam-support@uw.edu";

  public void setReplyTo(String replyTo) {
    this.replyTo = replyTo;
  }

  private String from = "UW Certificate Services <iam-support@uw.edu>";

  public void setFrom(String from) {
    this.from = from;
  }

  // test that mail works
  public void init() {
    try {
      this.mailSender.testConnection();
      log.info("Mail sender connection verified.");
    } catch (MessagingException e) {
      log.error("Unable to use the mail sender: " + e);
      this.active = false;
    }
  }

  private String[] doNotMail = null;

  public void setDoNotMail(String[] nom) {
    this.doNotMail = nom;
  }

  // create a standard message with the headers
  private MimeMessage genMimeMessage(IamMailMessage msg) {
    MimeMessage mime = mailSender.createMimeMessage();
    try {
      mime.setRecipients(RecipientType.TO, InternetAddress.parse(msg.getTo()));
      mime.setSubject(msg.makeSubstitutions(msg.getSubject()));
      mime.setReplyTo(InternetAddress.parse(replyTo));
      mime.setFrom(new InternetAddress(from));
      mime.addHeader("X-Auto-Response-Suppress", "NDR, OOF, AutoReply");
      mime.addHeader("Precedence", "Special-Delivery, never-bounce");
      mime.setText(msg.makeSubstitutions(msg.getText()));
    } catch (MessagingException e) {
      log.error("iam mail build fails: " + e);
    }
    return mime;
  }

  // send mail
  public void send(IamMailMessage msg) {
    MimeMessage mime = genMimeMessage(msg);
    if (active) mailSender.send(mime);
  }

  // send mail with owner cc
  public void sendWithOwnerCc(IamMailMessage msg, DNSVerifier verifier, List<String> cns) {

    MimeMessage mime = genMimeMessage(msg);
    try {
      List<String> owners = new Vector();
      for (int i = 0; i < cns.size(); i++) verifier.isOwner(cns.get(i), null, owners);
      List<Address> oAddrs = new ArrayList<Address>();
      for (int i = 0; i < owners.size(); i++) {
        boolean send = true;
        if (doNotMail != null) {
          for (int j = 0; j < doNotMail.length; j++) {
            if (doNotMail[j].equals(owners.get(i))) {
              log.debug("donotsend: " + owners.get(i));
              send = false;
            }
          }
        }
        if (send) {
          oAddrs.add(new InternetAddress(owners.get(i) + "@uw.edu"));
          log.debug(" cc to: " + owners.get(i));
        }
      }
      Address[] ccs = oAddrs.toArray(new Address[oAddrs.size()]);
      mime.setRecipients(RecipientType.CC, ccs);
      if (active) mailSender.send(mime);
    } catch (DNSVerifyException ex) {
      log.error("checking dns: " + ex.getMessage());
    } catch (SMTPSenderFailedException e) {
      log.error("cannot send email: " + e);
    } catch (SMTPAddressFailedException e) {
      log.error("cannot send email: " + e);
    } catch (MessagingException e) {
      log.error("iam mail failure: " + e);
    }
  }
}
