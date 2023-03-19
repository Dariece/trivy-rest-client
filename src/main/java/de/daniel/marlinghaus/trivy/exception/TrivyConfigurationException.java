package de.daniel.marlinghaus.trivy.exception;

import java.util.List;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class TrivyConfigurationException extends RuntimeException{
  private final HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
  private final int exitCode;
  private final List<String> errors;

  public TrivyConfigurationException(String message, int exitCode, List<String> errors){
    super(message);
    this.exitCode = exitCode;
    this.errors = errors;
  }
}
