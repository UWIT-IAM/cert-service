/* ========================================================================
 * Copyright (c) 2012 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

package edu.washington.iam.tools;

// mail message extension
// mostly holds parameters

public class IamMailMessage {

  private String from;
  private String replyTo;
  private String to; // comma separated lists
  private String cc;
  private String bcc;
  private String subject;
  private String text;

  // substution values
  private String certcn = "";
  private String certid = "";
  private String issuer = "";

  public void setSubstitutions(String cn, String id, String is) {
    this.certcn = cn;
    this.certid = id;
    this.issuer = is;
  }

  public String makeSubstitutions(String text) {
    return text.replaceAll("CERTCN", certcn)
        .replaceAll("CERTID", certid)
        .replaceAll("NL", "\n")
        .replaceAll("ISSUER", issuer);
  }

  public IamMailMessage() {}

  public IamMailMessage(IamMailMessage src) {
    this.from = src.getFrom();
    this.replyTo = src.getReplyTo();
    this.to = src.getTo();
    this.cc = src.getCc();
    this.bcc = src.getBcc();
    this.subject = src.getSubject();
    this.text = src.getText();
  }

  public void setFrom(String from) {
    this.from = from;
  }

  public String getFrom() {
    return this.from;
  }

  public void setReplyTo(String replyTo) {
    this.replyTo = replyTo;
  }

  public String getReplyTo() {
    return replyTo;
  }

  public void setTo(String to) {
    this.to = to;
  }

  public String getTo() {
    return to;
  }

  public void setCc(String cc) {
    this.cc = cc;
  }

  public String getCc() {
    return cc;
  }

  public void setBcc(String bcc) {
    this.bcc = bcc;
  }

  public String getBcc() {
    return bcc;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  public String getSubject() {
    return this.subject;
  }

  public void setText(String text) {
    this.text = text;
  }

  public String getText() {
    return this.text;
  }
}
