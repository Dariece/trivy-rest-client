package de.daniel.marlinghaus.trivy.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class InputErrorException extends Exception{
  private final HttpStatus status;

  public InputErrorException(String message){
    super(message);
    status = HttpStatus.BAD_REQUEST;
  }
}
