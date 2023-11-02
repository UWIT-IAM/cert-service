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

import java.util.Date;

/* Certificate broker history */

public class CBHistory {
  public static final int CB_HIST_REQ = 1;
  public static final int CB_HIST_REN = 2;
  public static final int CB_HIST_REV = 3;

  public int event;
  public Date eventTime;
  public String netid;

  public int getEvent() {
    return event;
  }

  public Date getEventTime() {
    return eventTime;
  }

  public String getNetid() {
    return netid;
  }
}
