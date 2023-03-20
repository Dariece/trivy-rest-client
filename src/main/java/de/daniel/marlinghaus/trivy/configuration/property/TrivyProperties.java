package de.daniel.marlinghaus.trivy.configuration.property;

import java.net.URI;
import java.nio.file.Path;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "trivy")
@Getter
@Setter
public class TrivyProperties {

  public Path tmpDirectory;
  public Path binDirectory;
  public URI host;
  public Integer processTimeout;
}
