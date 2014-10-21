/* ========================================================================
 * Copyright (c) 2010 The University of Washington
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

import java.util.List;
import java.util.Vector;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;


public final class XMLHelper {

    private XMLHelper() {}

    /**
     * Get child element by name, ignoring namespace declarations
     *
     * @param ele parent element
     * @param name name of element to find
     */
    public static Element getElementByName(Element ele, String name) {
       List<Element> list = getElementsByName(ele, name);
       if (list.size()>0) return list.get(0);
       return null;
    }

    /**
     * Get child elements by name, ignoring namespace declarations
     *
     * @param ele parent element
     * @param name name of elements to find
     */
    public static List<Element> getElementsByName(Element ele, String name) {
        Vector<Element> list = new Vector();
        NodeList nl = ele.getChildNodes();
        for (int j=0; j<nl.getLength(); j++) {
           if (nl.item(j).getNodeType()!=Node.ELEMENT_NODE) continue;
           Element e = (Element)nl.item(j);
           String n = e.getNodeName();
           if (matches(n, name)) list.add(e);
        }
        return (list);
    }
               

    /**
     * Get child element by classname
     *
     * @param ele parent element
     * @param classname of elements to find
     */
    public static Element getElementByClass(Element ele, String name) {
       List<Element> list = getElementsByClass(ele, name);
       if (list.size()>0) return list.get(0);
       return null;
    }

    /**
     * Get child elements by classname
     *
     * @param ele parent element
     * @param classname of elements to find
     */
    public static List<Element> getElementsByClass(Element ele, String cname) {
        Vector<Element> list = new Vector();
        NodeList nl = ele.getChildNodes();
        for (int j=0; j<nl.getLength(); j++) {
           if (nl.item(j).getNodeType()!=Node.ELEMENT_NODE) continue;
           Element e = (Element)nl.item(j);
           if (e.getAttribute("class").equals(cname)) list.add(e); 
        }
        return (list);
    }
               

    /**
     * Simple compare of strings without namespace preface
     *
     * @param nsname name with possible ns preface
     * @param name name to compare
     */
    public static boolean matches(String nsname, String name) {
       int col = nsname.indexOf(":");
       if (col>0) nsname = nsname.substring(col+1);
       return (nsname.matches(name));
    }
}

