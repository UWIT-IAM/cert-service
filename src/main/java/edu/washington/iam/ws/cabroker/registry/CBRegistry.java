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

import java.io.Serializable;
import java.util.List;
import java.util.Vector;

import java.util.Date;
import java.text.SimpleDateFormat;
import java.text.DateFormat;

import org.w3c.dom.Document;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.postgresql.jdbc3.Jdbc3PoolingDataSource;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;


import edu.washington.iam.ws.cabroker.exception.CBRegistryException;
import edu.washington.iam.ws.cabroker.exception.CBNotFoundException;
import edu.washington.iam.ws.cabroker.exception.CertificateManagerException;


/* registry access */

public class CBRegistry {
    
   private final Logger log =  LoggerFactory.getLogger(getClass());

   private Jdbc3PoolingDataSource dataSource;
   private String serverName = "localhost";
   private String databaseName = "cbregistry";
   private String user;
   private String password;

   public CBCertificate getCertificate(int id) throws CBNotFoundException {
       List<CBCertificate> certs = getCertificates(id, null, null, true, true);
       if (certs.size()==0) throw new CBNotFoundException();
       return certs.get(0);
   }

   public List<CBCertificate> getCertificates(String owner) {
       return getCertificates(0, owner, null, true, true);
   }

   public List<CBCertificate> getCertificates(String owner, String name) {
       return getCertificates(0, owner, name, true, true);
   }

   public List<CBCertificate> getCertificates(String owner, String name, boolean uwca, boolean icca) {
       return getCertificates(0, owner, name, uwca, icca);
   }

   public List<CBCertificate> getCertificates(int id, String owner, String name, boolean uwca, boolean icca) {

       List<CBCertificate> certs = new Vector<CBCertificate>();
       if (id==0 && name==null && owner==null) return null;
       Connection conn = null;
       Statement stmt = null;
       int ret = 0;
       try {
          conn = dataSource.getConnection();
          stmt = conn.createStatement();
          String query = "select distinct certificate.id as id,dn,cn,ca,caid,revokepass,renewid,status,requested,issued,expires from certificate";
          if (id>0) query = query + " where id="+id;
          else if (name!=null && name.length()>0) query = query + ",name where certificate.id=name.id and name.name like '%"+name+"%' ";
          else if (owner!=null && owner.length()>0) query = query + ",owner where certificate.id=owner.id and owner.netid='"+owner+"' ";
          if (!uwca) query = query + " and ca!=1 ";
          if (!icca) query = query + " and ca!=2 ";
          query = query + " order by cn";
 
          log.debug("search query: " + query);
           
          ResultSet rs = stmt.executeQuery(query);
          while (rs.next()) {
             CBCertificate cert = new CBCertificate();
             cert.status = rs.getInt("status");
             if (cert.status==CBCertificate.CERT_STATUS_GONE) continue;
             cert.id = rs.getInt("id");
             cert.ca = rs.getInt("ca");
             cert.dn = rs.getString("dn");
             cert.cn = rs.getString("cn");
             cert.caId = rs.getInt("caid");
             cert.revokePass = rs.getString("revokepass");
             cert.status = rs.getInt("status");
             cert.renewId = rs.getString("renewid");
             Timestamp ts =  rs.getTimestamp("expires");
             if (ts!=null) cert.expires = new Date(ts.getTime());
             cert.registry = this;
             certs.add(cert);
          }
      
       } catch (SQLException e ) {
         log.debug("sql excp" + e);
         ret = 1;
       }
       try {
         if (stmt != null) stmt.close();
         if (conn!=null) conn.close();
       } catch (SQLException e ) {
         log.debug("closing excp" + e);
         ret = 1;
       }
      
      return certs;
   }

   public List<CBCertificate> getWaitingCertificates(int ca) {

       List<CBCertificate> certs = new Vector<CBCertificate>();
       if (ca==0) return null;
       Connection conn = null;
       Statement stmt = null;
       int ret = 0;
       try {
          conn = dataSource.getConnection();
          stmt = conn.createStatement();
          String query = "select distinct certificate.id as id,dn,cn,ca,caid,status,renewid from certificate where ca=" + 
             String.valueOf(ca) + " and " +
             " (status=" + String.valueOf(CBCertificate.CERT_STATUS_REQUESTED) +
             " or status=" + String.valueOf(CBCertificate.CERT_STATUS_RENEWING) + ")";
 
          log.debug("wating search query: " + query);
           
          ResultSet rs = stmt.executeQuery(query);
          while (rs.next()) {
             CBCertificate cert = new CBCertificate();
             cert.id = rs.getInt("id");
             cert.ca = rs.getInt("ca");
             cert.dn = rs.getString("dn");
             cert.cn = rs.getString("cn");
             cert.caId = rs.getInt("caid");
             cert.status = rs.getInt("status");
             cert.renewId = rs.getString("renewid");
             cert.registry = this;
             certs.add(cert);
          }
      
       } catch (SQLException e ) {
         log.debug("sql excp" + e);
         ret = 1;
       }
       try {
         if (stmt != null) stmt.close();
         if (conn!=null) conn.close();
       } catch (SQLException e ) {
         log.debug("closing excp" + e);
         ret = 1;
       }
      
      return certs;
   }

   // get the cert timestamp
   public long getCertificateTS() {
      Connection conn = null;
      Statement stmt = null;
      long ret = 0;
      try {
          conn = dataSource.getConnection();
          stmt = conn.createStatement();
          String query = "select cert_update_time from db_ts";
          ResultSet rs = stmt.executeQuery(query);
          while (rs.next()) {
            ret = rs.getLong("cert_update_time");
            break;
          }
      } catch (SQLException e ) {
         log.debug("get ts excp: " + e);
      }
      try {
         if (stmt!=null) stmt.close();
         if (conn!=null) conn.close();
      } catch (SQLException e ) {
         log.debug("get ts excp on close: " + e);
      }
      log.debug("cert ts = " + ret);
      return ret;
   }

   // update the cert timestamp
   private void updateCertificateTS(Connection conn) {
      Date now = new Date();
      Statement stmt = null;
      try {
         stmt = conn.createStatement();
         stmt.executeUpdate("update db_ts set cert_update_time=" + now.getTime());
      } catch (SQLException e ) {
         log.debug("uopdate ts excp: " + e);
      }
      try {
         if (stmt!=null) stmt.close();
      } catch (SQLException e ) {
         log.debug("uopdate ts excp on close: " + e);
      }
   }

   // update variable stuff (status and etc from the ca)
   public int updateCertificate(CBCertificate cert) {
      log.debug("update cert " + cert.id);
      if (cert.id==0) return 0;
      Connection conn = null;
      Statement stmt = null;
      int ret = 1;
      try {
         CBCertificate old = getCertificate(cert.id);
         if ( (cert.status!=old.status) || (cert.dn!=null && !cert.dn.equals(old.dn)) ||
              (cert.expires!=null && !cert.expires.equals(old.expires)) ||
              (cert.renewId!=null && !cert.renewId.equals(old.renewId)) ) {
             conn = dataSource.getConnection();
             stmt = conn.createStatement();
         }
         if (cert.status!=old.status) stmt.executeUpdate("update certificate set status=" + cert.status + " where id=" + cert.id);
         if (cert.dn!=null && !cert.dn.equals(old.dn)) {
            stmt.executeUpdate("update certificate set dn='" + cert.dn + "' where id=" + cert.id);
         }
         if (cert.expires!=null && !cert.expires.equals(old.expires)) {
            DateFormat formatter = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
            log.debug("update certificate set expires='" + formatter.format(cert.expires) + "' where id=" + cert.id);
            stmt.executeUpdate("update certificate set expires='" + formatter.format(cert.expires) + "' where id=" + cert.id);
         }
         if (cert.renewId!=null && !cert.renewId.equals(old.renewId)) {
            stmt.executeUpdate("update certificate set renewid='" + cert.renewId + "' where id=" + cert.id);
         }
         if (conn!=null) updateCertificateTS(conn);
         if (stmt!=null) stmt.close();
         if (conn!=null) conn.close();
       } catch (CBNotFoundException e ) {
         log.debug(" not found for update" + e);
         ret = 0;
       } catch (SQLException e ) {
         log.debug(" excp" + e);
         ret = 0;
      }
      try {
         if (stmt!=null) stmt.close();
         if (conn!=null) conn.close();
      } catch (SQLException e ) {
         log.debug(" excp on close" + e);
      }
      return ret;
   }


   public int deleteCertificate(int cert) {
      return 0;
   }

   private void putNames(CBCertificate cert, Connection conn) throws SQLException {
      log.debug("adding " + cert.names.size() + " altnames");
      Statement stmt = conn.createStatement();
      for (int i=0; i<cert.names.size(); i++) {
         String cmd = "insert into name values ("+cert.id+",'"+cert.names.get(i)+"')"; 
         stmt.executeUpdate(cmd);
      }
      stmt.close();
   }

   private void putOwners(CBCertificate cert, Connection conn) throws SQLException {
      log.debug("adding " + cert.owners.size() + " owners");
      Statement stmt = conn.createStatement();
      for (int i=0; i<cert.owners.size(); i++) {
         String cmd = "insert into owner values ("+cert.id+",'"+cert.owners.get(i)+"')"; 
         stmt.executeUpdate(cmd);
      }
      stmt.close();
   }

   public int addOwner(int id, String user) {
      try {
         Connection conn = dataSource.getConnection();
         Statement stmt = conn.createStatement();
         stmt.executeUpdate("insert into owner values (" + id + ",'" + user + "')");
         stmt.close();
         conn.close();
       } catch (SQLException e ) {
         log.debug("put owner excp" + e);
         return 500;
      }
      return 200;
   }

   public int deleteOwner(int id, String user) {
      try {
         Connection conn = dataSource.getConnection();
         Statement stmt = conn.createStatement();
         stmt.executeUpdate("delete from owner where id=" + id + " and netid='" + user + "'");
         stmt.close();
         conn.close();
       } catch (SQLException e ) {
         log.debug("del owner excp" + e);
         return 500;
      }
      return 200;  // just indicate a good return.
   }

   public void putCertificate(CBCertificate cert) throws CertificateManagerException {
       log.debug("db put cert");
       Connection conn = null;
       Statement stmt = null;
       int ret = 0;
       String emsg = null;
       try {
          conn = dataSource.getConnection();
          stmt = conn.createStatement();
          String safeDn = cert.dn.replaceAll("'", "''");
          String cmd = "insert into certificate (dn,cn,ca,caid,status) values ('"+
            safeDn+"','"+cert.cn+"',"+cert.ca+","+cert.caId+","+cert.status+")";
          log.debug("put=" + cmd);
          stmt.executeUpdate(cmd);
    
          // get the id
          stmt = conn.createStatement();
          String query = "select currval('certificate_id_seq')";
          ResultSet rs = stmt.executeQuery(query);
          while (rs.next()) {
             cert.id = rs.getInt("currval");
             log.debug("put cert created index " + cert.id);
             break;
          }
      
          putNames(cert, conn);
          putOwners(cert, conn);
   
          updateCertificateTS(conn);
          
       } catch (SQLException e ) {
         log.debug("sql excp" + e);
         emsg = e.getMessage();
         ret = 1;
       }
       try {
         if (stmt != null) stmt.close();
         if (conn!=null) conn.close();
       } catch (SQLException e ) {
         log.debug("closing excp" + e);
         emsg = e.getMessage();
         ret = 1;
       }
       if (ret==1) throw new CertificateManagerException(emsg);
   }


   public void getNames(CBCertificate cert) {

       cert.names = new Vector<String>();

       Connection conn = null;
       Statement stmt = null;
       int ret = 0;
       try {
          conn = dataSource.getConnection();
          stmt = conn.createStatement();
          String query = "select name from name where id='" + cert.id + "'";
           
          ResultSet rs = stmt.executeQuery(query);
          while (rs.next()) {
             cert.names.add(rs.getString("name"));
          }
      
       } catch (SQLException e ) {
         log.debug("sql excp" + e);
         ret = 1;
       }
       try {
         if (stmt != null) stmt.close();
         if (conn!=null) conn.close();
       } catch (SQLException e ) {
         log.debug("closing excp" + e);
         ret = 1;
       }
   }


   public void getOwners(CBCertificate cert) {

       cert.owners = new Vector<String>();

       Connection conn = null;
       Statement stmt = null;
       int ret = 0;
       try {
          conn = dataSource.getConnection();
          stmt = conn.createStatement();
          String query = "select netid from owner where id='" + cert.id + "'";
           
          ResultSet rs = stmt.executeQuery(query);
          while (rs.next()) {
             cert.owners.add(rs.getString("netid"));
          }
      
       } catch (SQLException e ) {
         log.debug("sql excp" + e);
         ret = 1;
       }
       try {
         if (stmt != null) stmt.close();
         if (conn!=null) conn.close();
       } catch (SQLException e ) {
         log.debug("closing excp" + e);
         ret = 1;
       }
   }

   public void getHistory(CBCertificate cert) {

       cert.history = new Vector<CBHistory>();

       Connection conn = null;
       Statement stmt = null;
       int ret = 0;
       try {
          conn = dataSource.getConnection();
          stmt = conn.createStatement();
          String query = "select event,event_time,netid from history where id='" + cert.id + "' order by event_time";
           
          ResultSet rs = stmt.executeQuery(query);
          while (rs.next()) {
             CBHistory h = new CBHistory();
             h.event = rs.getInt("event");
             Timestamp ts =  rs.getTimestamp("event_time");
             if (ts!=null) h.eventTime = new Date(ts.getTime());
             h.netid = rs.getString("netid");
             cert.history.add(h);
          }
      
       } catch (SQLException e ) {
         log.debug("sql excp" + e);
         ret = 1;
       }
       try {
         if (stmt != null) stmt.close();
         if (conn!=null) conn.close();
       } catch (SQLException e ) {
         log.debug("closing excp" + e);
         ret = 1;
       }
   }
   
   public int addHistory(CBCertificate cert, int event, Date et, String user) {
      try {
         Connection conn = dataSource.getConnection();
         Statement stmt = conn.createStatement();

         DateFormat formatter = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
         log.debug("add hist time=" + formatter.format(et));
         stmt.executeUpdate("insert into history (id,event, event_time, netid) values " + 
              " (" + cert.id + "," + event + ",'" + formatter.format(et) + "','" + user + "')");
         stmt.close();
         conn.close();
      } catch (SQLException e ) {
         log.debug("put history excp" + e);
         return 500;
      }
      return 200;
   }

   // get the id of a remote cert
   public int getCertificateId(int ca, int caid) {

      Connection conn = null;
      Statement stmt = null;
      int ret = 0;
      try {
         conn = dataSource.getConnection();
         stmt = conn.createStatement();
         String query = "select id from certificate where ca=" + ca + " and caid=" + caid;
 
         log.debug("find id query: " + query);
           
         ResultSet rs = stmt.executeQuery(query);
         while (rs.next()) {
            ret = rs.getInt("id");
         }
      
      } catch (SQLException e ) {
         log.debug("sql excp" + e);
         ret = 0;
      }
      try {
         if (stmt != null) stmt.close();
         if (conn!=null) conn.close();
      } catch (SQLException e ) {
         log.debug("closing excp" + e);
         ret = 0;
      }
      
      return ret;
   }


   // get the ca int value from a string
   public static int getCaFromString(String ca) {
      if (ca==null || ca.length()==0) return (-1);
      if (ca.equalsIgnoreCase(CBCertificate.UW_CA_KEY)) return CBCertificate.UW_CA;
      if (ca.equalsIgnoreCase(CBCertificate.IC_CA_KEY)) return CBCertificate.IC_CA;
      return (-1);
   }

   public void setServerName(String v) {
      serverName = v;
   }
   public void setDatabaseName(String v) {
      databaseName = v;
   }
   public void setUser(String v) {
      user = v;
   }
   public void setPassword(String v) {
      password = v;
   }

   /* init */
   public void init() {
       dataSource = new Jdbc3PoolingDataSource();
       dataSource.setDataSourceName("CB source");
       dataSource.setServerName(serverName);
       dataSource.setDatabaseName(databaseName);
       dataSource.setUser(user);
       dataSource.setPassword(password);
       dataSource.setMaxConnections(10);
       log.debug("datasource initialized");
   }

   public void cleanup() {
   }

}
