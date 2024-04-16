/* ========================================================================
 * Copyright (c) 2013 The University of Washington
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

/*  Iam extended Dialog Widget
 *
 *  Extends dijit Dialog with sizing and positioning, and
 *  submit and cancel button on the bottom.
 *
 *  by Fox
 */

define([
  "dojo/_base/declare",
  "dijit/Dialog",
  "dojo/keys",
  "dojo/_base/event",
  "dijit/_TemplatedMixin",
  "dijit/_WidgetsInTemplateMixin",
  "dojo/text!/cs/js/templates/Dialog.html"
 ],function(declare, Dialog, keys, event, _TemplatedMixin, _WidgetsInTemplateMixin, template) {

     var _logit = function() { console.log('submit'); };

     return declare([Dialog, _TemplatedMixin, _WidgetsInTemplateMixin], {
         templateString: template,
         _noScript: true,

         submitLabel: "",   // default is to not display
         cancelLabel: "",
         submitAction: '_logit()',
         cancelAction: null,
         placeOver: null,
         rightMargin: "100px",

         // catch tabs and include our buttons in the sequence
         _onKey: function(evt) {
            if(evt.charOrCode === keys.TAB){
                var node = evt.target;
                var next = 0;
                // check tabbing from end of list
                if (!evt.shiftKey){
                   if (node == this._lastFocusItem){
                      console.log('switch to submit');
                      if (this.submitLabel!='') {
                         this.submitButtonNode.focus();
                         event.stop(evt);
                      } else next = 1;
                   }
                   if (next || node == this.submitButtonNode){
                      console.log('switch to cancel');
                      if (this.cancelLabel!='') {
                         this.cancelButtonNode.focus();
                         event.stop(evt);
                         next = 0;
                      } else next = 1;
                   }
                   if (next || node == this.cancelButtonNode){
                      console.log('back to top');
                      this._firstFocusItem.focus();
                      event.stop(evt);
                   }
                } else { // reverse tab
                   if (node == this._firstFocusItem){
                      if (this.cancelLabel!='') {
                         this.cancelButtonNode.focus();
                         event.stop(evt);
                      } else next = 1;
                   }
                   if (next || node == this.cancelButtonNode){
                      console.log('reverse to submit');
                      if (this.submitLabel!='') {
                         this.submitButtonNode.focus();
                         event.stop(evt);
                         next = 0;
                      } else next = 1;
                   }
                   if (next || node == this.submitButtonNode){
                      console.log('back to bottom');
                      this._lastFocusItem.focus();
                      event.stop(evt);
                   }
                }
            } else this.inherited(arguments);
         },

         // on show set width like target and place on right
         show: function(){
            console.log('iamdialog show');
            var dom;
            var dp;
            var ds;
            var nw=10;
            var placeNode = null;
            require(["dojo/dom", "dojo/dom-geometry", "dojo/dom-style"], function(d, dg, s){
              dom = d;
              dp = dg;
              ds = s;
            });

            // set width
            if (this.placeOver!=null) {
               console.log('over: '+this.placeOver);
               placeNode = dom.byId(this.placeOver);
               if (placeNode!=null) {
                 var dw = dp.position(placeNode,true).w;
                 console.log('over w=' + dw);
                 nw = dw - dw/6;
                 console.log('nw=' + nw);
                 ds.set(this.containerNode, {
                    width: '300px'
                 });
              } else console.log('over node not found');
            }

            // show and position
            this.inherited(arguments);

            if (placeNode!=null) {
               ds.set(this.domNode, {
                  right: '40px'
               });
            }
            var dw = dp.position(this.domNode,true).w;
            var dx = dp.position(this.domNode,true).x;
            console.log('dialog show complete x=' + dx + ' w=' + dw);

            // drop buttons if not wanted
            if (this.submitLabel=='') {
               ds.set(this.submitButtonNode, {
                  display: 'none'
               });
            }
            if (this.cancelLabel=='') {
               ds.set(this.cancelButtonNode, {
                  display: 'none'
               });
            }
         },

         clickSubmit: function(){
            eval(this.submitAction);
         },
         clickCancel: function(){
            if (this.cancelAction!=null) eval(this.cancelAction);
            else this.hide();
         }
   });
});
