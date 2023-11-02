package edu.washington.iam.tools;

import org.apache.velocity.app.VelocityEngine;
import org.springframework.web.servlet.view.velocity.VelocityConfig;

/**
 * This stub class is needed to support the Spring-Velocity integration with the
 * latest versions of Spring and Velocity because the latest Spring version
 * no longer has a suitable implementation of the VelocityConfig interface.
 *
 * An instance of this class is populated with a VelocityEngine object and
 * is provided as a configuration item to the Spring webmvc framework.
 * This generally occurs in the XML configuration of Spring.
 */
public class IamVelocityConfig implements VelocityConfig {

  private VelocityEngine velocityEngine;

  public IamVelocityConfig() {}

  @Override
  public VelocityEngine getVelocityEngine() {
    return velocityEngine;
  }

  public void setVelocityEngine(VelocityEngine velocityEngine) {
    this.velocityEngine = velocityEngine;
  }
}
