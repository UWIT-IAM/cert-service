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

import java.util.List;

public interface DNSVerifier {

  /**
   * Test if a user has ownership of a domain
   *
   * @param id user's uwnetid
   * @param domain to test
   * @param return list of owners (can be null)
   */
  public boolean isOwner(String dns, String id, List<String> owners) throws DNSVerifyException;

  public boolean isOwner(String dns, String id) throws DNSVerifyException;
}
