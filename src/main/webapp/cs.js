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

// cert service javascript

// Trim leading and following spaces from a string
String.prototype.trim = function () {
   return this.replace(/^\s*|\s*$/g,"");
}

// common vars
var v_root = '/test_ws/v1';
var v_remoteUser = '';
var v_xsrf = '';
var v_etag = '';
var v_loadErrorMessage = "Operation failed. You may need to reload the page to reauthenticate";

var v_certId = '';

var v_cert_ts = 0;

function pad(number, length) {
    var str = '' + number;
    while (str.length < length) {
        str = '0' + str;
    }
    return str;
}

// '000nnn' -> 'nnn'
function stripZeros(i) {
    return i.replace(/^0*/,'');
}

// 'yyyy/mm/dd' -> 'mm/dd/yyyy'
function flipDate(d) {
   if (d.length==0) return d;
   return d.substring(5) + '/' + d.substring(0,4);
}

// Prevent Enter from submitting a form
function noenter(e)
{
  if (!e) e = window.event;
  return !(e && e.keyCode == 13);
}

var certLister = null;

function refreshCertsIfNeeded() {
   console.log('refresh if needed');
   if (certLister==null) return;
   iam_getRequest(v_root + '/ajaxTs', {'Accept': 'application/json'}, 'json', function(data, args) {
        console.log('verify ts');
        console.log(data);
        console.log(data.timestamp);
        ts = data.timestamp;
        if (ts>v_cert_ts) {
           console.log('cert listr refresh needed');
           certLister();
           v_cert_ts = ts;
        }
      });
}

/* set the panel sizes */

function setPaneSizes() {
   console.log('adjust cs panels');
   var cw = contentWidth;
   var th = dojo.position(dojo.byId('titlebar'),true).h;
   
   var ch = contentHeight - th - 40;;
   var ct = contentTop + th + 10;

   var pan = dojo.byId('cscontent');
   if (pan!=null) dojo.style(pan, {
      height: ch + 'px',
      width: cw + 'px'
   });

   cw = contentWidth/2 - 20;
   console.log('left: w=' + cw + ', h=' + ch)
   pan = dojo.byId('leftsideIndex');
   if (pan!=null) dojo.style(pan, {
      height: ch + 'px'
   });

   var sw = cw - 20;
   var sh = ch - 20;
   console.log('list: w=' + sw + ', h=' + sh)
   pan = dojo.byId('searchResult');
   if (pan!=null) dojo.style(pan, {
      height: sh + 'px'
   });

   cw = cw - 30;
   ch = ch - 30;
   console.log('right: w=' + cw + ', h=' + ch)
   pan = dojo.byId('certDisplay');
   if (pan!=null) dojo.style(pan, {
      height: ch + 'px',
      width: cw + 'px'
   });

}


/* Cert store */

var certsStore = null;
var certsGrid = null;


// other possible fields
/*
            {
                field: "caid",
                name: "CA id",
                width: '5em',
                styles: "text-align:right;",
                formatter: function(item) {
                    return stripZeros(item.toString()) + '&nbsp;';
                }
            },
*/

var certTableLayout = [ [
            {
                field: "no",
                name: "No.",
                width: '3.5em',
                styles: "text-align:right;",
                formatter: function(item) {
                    return stripZeros(item.toString()) + '&nbsp;';
                }
            },
            {
                field: "cn",
                name: "CN",
                width: '20em',
                formatter: function(item) {
                    return item.toString();
                }
            },
            {
                field: "ca",
                name: "CA",
                width: '2em',
                formatter: function(item) {
                    return item.toString();
                }
            },
            {
                field: "status",
                name: "Status",
                width: '4em',
                formatter: function(item) {
                    return item.toString();
                }
            },
            {
                field: "expires",
                name: "expires",
                width: '6em',
                formatter: function(item) {
                    return flipDate(item.toString());
                }
            }]];

// act on a click on a row
function doRowAction(e) {
  if (e.button==2) return true;
  var item = certsGrid.getItem(e.rowIndex);
  var status = certsGrid.store.getValue(item, 'status');
  var id = certsGrid.store.getValue(item, 'no');
  var url = v_root + '/cert?innerview=yes&id=' + stripZeros(id.toString());
  dijit.byId('certDisplay').set('errorMessage', 'Your session had expired.  Reload the page to reauthenticate.');
  dijit.byId('certDisplay').set('href', url);
  dijit.byId('certDisplay').set('onLoad', refreshCertsIfNeeded);
  v_certId = id;
  // dojo.byId('selectTitlePane').innerHTML = '<tt>' + certsGrid.store.getValue(item, 'cn') + '</tt>';
  // dojo.byId('selectTitlePane').innerHTML = '<tt>' + e.button + '</tt>';
  
  return false;
}

function styleRow(row) {
  // console.log('styleRow:: ' + row.index + ' sel=' + row.selected + ' min=' + row.over);
  var item = certsGrid.getItem(row.index);
  if (item!=null) {
    var color = '#000000';
    var status = certsGrid.store.getValue(item, 'status');
    if (status=='expired' || status=='revoked') color = '#900000';
    else if (status=='request') color = '#000090';
    var view = certsGrid.views.views[0];
    var node = view.getCellNode(row.index,0);
    dojo.style(node, "color", color);
    node = view.getCellNode(row.index,3);
    dojo.style(node, "color", color);
  }

}


function getCertsStore() {
  certsStore = new dojox.data.XmlStore({
    url: '/cs/ajaxSearch',
    label: 'certs',
    sendQuery: true
  });
}

function clearOldGrid() {
   if (certsGrid!=null) {
      certsStore.close();
      certsGrid.destroyRecursive();
   }
}

var showCertsName = '';

function showCerts(name) {
   showCertsName = name;
   dojo.byId('searchTitlePane').innerHTML = "Certificates matching '" + name + "'";
   certLister = _showCerts;
   v_cert_ts = 0;
   refreshCertsIfNeeded();
   iam_bannerNotice('showing certs');
}

// 
function setSort(t) {
  require(["dojo/dom-class"], function(domClass){
    if (t=='name') {
      v_useDsp = 1;
      domClass.add('sortNameBtn', 'sortChooserOn');
      domClass.remove('sortIdBtn', 'sortChooserOn');
    } else {
      v_useDsp = 0;
      domClass.add('sortIdBtn', 'sortChooserOn');
      domClass.remove('sortNameBtn', 'sortChooserOn');
    }
    showGroupSearch(myGroupList);
  });
}

function _showCerts() {
   clearOldGrid();

   getCertsStore();
   certsGrid = new dojox.grid.DataGrid({
     store: certsStore,
     query: {
        name: showCertsName
        },
     structure: certTableLayout,
     columnReordering: true,
     selectionMode: 'single',
     loadingMessage: 'searching for certificates',
     rowsPerPage: '20',
     autoWidth: true
   });
   dojo.connect(certsGrid, 'onCellFocus', setFocusStyle );
   dojo.connect(certsGrid, 'onRowClick', doRowAction);
   dojo.connect(certsGrid, 'onStyleRow', styleRow );
   dojo.connect(certsGrid, '_onFetchComplete', setPaneSizes);
   var tgt = dijit.byId('searchResult').containerNode.appendChild(certsGrid.domNode);
   certsGrid.startup();
}

// saved copy of home page html
var homeHtml = null;

function showMyCerts() {
   console.log('showMy');
   certLister = _showMyCerts;
   v_cert_ts = 0;
   refreshCertsIfNeeded();
}

// dojoxGridRowOver

function setFocusStyle(c, row) {
  var view = certsGrid.views.views[0];
  var node = view.getRowNode(row);
  require(["dojo/dom-class"], function(domClass){
   domClass.add(node, 'dojoxGridRowOver');
  });
}

function _showMyCerts() {
   console.log('showMy');

   clearOldGrid();
   dojo.byId('searchTitlePane').innerHTML = "Favorites";

   getCertsStore();
   certsGrid = new dojox.grid.DataGrid({
     store: certsStore,
     query: {
        owner: v_remoteUser
        },
     structure: certTableLayout,
     errorMessage: 'Your session has expired.  Reload the page to reauthenticate.'
   });
   console.log('conecting');
   dojo.connect(certsGrid, 'onCellFocus', setFocusStyle );
   dojo.connect(certsGrid, 'onRowClick', doRowAction);
   dojo.connect(certsGrid, 'onStyleRow', styleRow );
   dojo.connect(certsGrid, '_onFetchComplete', setPaneSizes);
   var tgt = dijit.byId('searchResult').containerNode.appendChild(certsGrid.domNode);
   console.log(tgt);
   certsGrid.startup();
}

function getCertList(name) {
  var url = v_root + '/search?innerview=yes&name=' + name;
  dijit.byId('searchResult').set('href',url);
}

function checkSimpleSearch(e)
{
  console.log(e);
  if (!e) e = window.event;
  if (e.keyCode==13) showCerts(dijit.byId('simplesearch').get('value'));
}


// cert functions

function remFav(response, ioArgs) {
  if (v_certId != '') {
   dojo.xhrDelete({
      url: v_root + '/ajax/owner?id=' + v_certId,
      handleAs: 'text',
      load: function (data){dojo.byId('remLink').innerHTML = "removed";},
      error: function (data){iam_showTheNotice('error: ' + data);}
      });
  }
}
function addFav() {
  if (v_certId != '') {
   dojo.xhrPut({
      url: v_root + '/ajax/owner?id=' + v_certId,
      handleAs: 'text',
         load: function (data){dojo.byId('addLink').innerHTML = "added";},
         error: function (data){iam_showTheNotice('error: ' + data);}
      });
  }
}

// right side heplers
function showNewIC() {
  // dojo.byId('selectTitlePane').innerHTML = 'InCommon certificate request';
  dijit.byId('certDisplay').set('href', v_root + '/req?type=ic&innerview=yes');
}
function showNewUW() {
  // dojo.byId('selectTitlePane').innerHTML = 'UWCA certificate request';
  dijit.byId('certDisplay').set('href', v_root + '/req?type=uw&innerview=yes');
}
function showVerify() {
  // dojo.byId('selectTitlePane').innerHTML = 'Verify DNS ownership';
  dijit.byId('certDisplay').set('href', v_root + '/req?type=ver&innerview=yes');
}
// new cert functions

function assembleRequestXml(type) {

   if (type=='uw') cert_ca = '1';
   else cert_ca = '2';

   var ct = dijit.byId(type + '_cert_type').get('value');
   var st = dijit.byId(type + '_server_type').get('value');
   var lt = dijit.byId(type + '_lifetime').get('value');
   var ns = dijit.byId(type + '_num_server').get('value');

   var xml = '<sslCertRequest certCa="' + cert_ca + '" certType="' + ct +
      '" serverType="' + st + '" lifetime="' + lt + '" numServer="' + ns + '">';

   // add the csr
   csr = dijit.byId(type + '_csr').get('value').trim();
   if (csr=='') {
      iam_showTheNotice("You must provide a csr");
      return '';
   }
   if (csr.indexOf('&')>=0||csr.indexOf('<')>=0||csr.indexOf('>')>=0) {
      iam_showTheNotice("Not a valid CSR");
      return '';
   }

   // add the headers if they were left off
   if (csr.indexOf('-----')<0) csr = '-----BEGIN CERTIFICATE REQUEST-----\n' + csr + '\n-----END CERTIFICATE REQUEST-----';
   xml = xml + '<csr>' + csr + '</csr>';

   // add altnames
   if (type=='ic') {
      altnames = dijit.byId(type + '_altname').get('value').trim().split(/[\s,]+/);
      xml = xml + '<altNames>';
      dojo.forEach(altnames, function(alt) {
         if (alt.indexOf('&')>=0||alt.indexOf('<')>=0||alt.indexOf('>')>=0) {
            iam_showTheNotice("Not valid altnames");
            return '';
         }
         if (alt!='') xml = xml + '<altName>' + alt + '</altName>';
        });
      xml = xml + '</altNames>';
   }

   xml = xml + '</sslCertRequest>';
   return xml;
}

function submitNewRequest(type) {
  var xml = assembleRequestXml(type);
  if (xml=='') return;
  document.body.style.cursor = 'wait';
  dojo.xhrPut({
     url: v_root + '/req',
     handleAs: 'text',
     putData: xml,
     load: function(data, args) {
        // iam_showTheNotice(args.xhr.status);
        if (args.xhr.status==200 || args.xhr.status==201) {
           dijit.byId('certDisplay').set('content', data);
        } else if (args.xhr.status==203) {
           dijit.byId('errorPopup').set('content', data);
           dijit.byId('errorPopup').show();
        } else iam_showTheNotice('response: ' + args.xhr.status);
        document.body.style.cursor = 'default';
      },
     error: function(data, args) {
        if (args.xhr.status==0) iam_showTheNotice('Please reload the page to reauthenticate.');
        else {
           dijit.byId('errorPopup').set('content', data);
           dijit.byId('errorPopup').show();
        }

/*
        if (args.xhr.status==401) iam_showTheNotice('Sorry. No permission for that request.<br/>Are you sure you own the domains?');
        else if (args.xhr.status==402) iam_showTheNotice('You must reauthenticate before submitting the request.');
        else if (args.xhr.status==400) iam_showTheNotice('Not a valid request.');
        else iam_showTheNotice('Sorry, the service responded with status: ' + args.xhr.status);
*/
        document.body.style.cursor = 'default';
      }
   });

}

function submitRenewRequest(id) {
  document.body.style.cursor = 'wait';
  dojo.xhrPut({
     url: v_root + '/renew?id=' + id,
     handleAs: 'text',
     putData: '',
     load: function(data, args) {
        // iam_showTheNotice(args.xhr.status);
        if (args.xhr.status==200 || args.xhr.status==201) {
           var url = v_root + '/cert?innerview=yes&id=' + id;
           dijit.byId('certDisplay').set('href', url);
        } else if (args.xhr.status==203) {
           dijit.byId('errorPopup').set('content', data);
           dijit.byId('errorPopup').show();
        } else iam_showTheNotice('response: ' + args.xhr.status);
        document.body.style.cursor = 'default';
      },
     error: function(data, args) {
        if (args.xhr.status==0) iam_showTheNotice('Please reload the page to reauthenticate.');
        else {
           dijit.byId('errorPopup').set('content', data);
           dijit.byId('errorPopup').show();
        }
        document.body.style.cursor = 'default';
      }
   });

}

function checkDnsLookup(e)
{
  console.log(e);
  if (!e) e = window.event;
  if (e.keyCode==13) doDnsTest();
}

function doDnsTest() {
   name = dijit.byId('dnsname').get('value').trim();
   if (name=='') return true;
   dojo.byId('dnsResult').innerHTML = "verifying";
   url = v_root + '/ajax/verify?dns=' + name;
   sub = 'You are';
   if ((s=name.indexOf(' '))>0) {
      url = v_root + '/ajax/verify?dns=' + name.substring(s+1).trim() + '&id=' + name.substring(0,s).trim();
      sub = name.substring(0,s).trim() + ' is';
   }
   console.log('dns lookup url: ' + url);
   dojo.xhrGet({
     url: url,
     handleAs: 'text',
     load: function(data, args) {
        dojo.byId('dnsResult').innerHTML = sub + " an owner of that domain.";
      },
     error: function(data, args) {
        if (args.xhr.status==404) dojo.byId('dnsResult').innerHTML = sub + " not an owner of that domain.";
        else dojo.byId('dnsResult').innerHTML = "DNS verification failed with status: " + args.xhr.status==404;
      }
   });
}

// show the incommon intermediate cert
function showInc() {
   dijit.byId('incDialog').show();
}
