package de.daniel.marlinghaus.trivy.configuration;

import de.daniel.marlinghaus.trivy.configuration.property.TrivyProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(TrivyProperties.class)
public class TrivyConfiguration {

}
