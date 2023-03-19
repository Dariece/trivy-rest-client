package de.daniel.marlinghaus.trivy.contoller;

import de.daniel.marlinghaus.trivy.exception.InputErrorException;
import de.daniel.marlinghaus.trivy.exception.TrivyConfigurationException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

@RestControllerAdvice
@Slf4j
public class DefaultControllerAdvice {

  @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
  public final ResponseEntity<?> handleException(
      org.springframework.http.converter.HttpMessageNotReadableException exception) {
    return buildErrorResponse(exception.getMessage(), HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(MaxUploadSizeExceededException.class)
  public final ResponseEntity<?> handleMaxUploadSizeExceededException(
      MaxUploadSizeExceededException exception) {
    return buildErrorResponse(exception.getMessage(), HttpStatus.PAYLOAD_TOO_LARGE);
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<?> handleException(MethodArgumentNotValidException exception) {
    final String violationMsg = exception.getBindingResult().getAllErrors().stream()
        .map(DefaultMessageSourceResolvable::getDefaultMessage).collect(Collectors.joining(", "));
    return buildErrorResponse(violationMsg, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(ConstraintViolationException.class)
  public ResponseEntity<?> handleException(ConstraintViolationException exception) {
    final String violationMsg = exception.getConstraintViolations().stream()
        .map(ConstraintViolation::getMessage).collect(Collectors.joining(", "));
    return buildErrorResponse(violationMsg, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(MethodArgumentTypeMismatchException.class)
  public ResponseEntity<?> handleException(MethodArgumentTypeMismatchException exception) {
    return buildErrorResponse(
        String.format("Invalid type for parameter %s with value %s", exception.getName(),
            exception.getValue()), HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<?> handleException(MissingServletRequestParameterException exception) {
    return buildErrorResponse(
        String.format("Parameter %s is missing", exception.getParameterName()),
        HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(value = {Exception.class, RuntimeException.class})
  public ResponseEntity<?> handleException(Exception exception) {
    return buildErrorResponse(
        String.format("Unknown server error occurred \"%s\"", exception.getMessage()),
        HttpStatus.INTERNAL_SERVER_ERROR);
  }

  @ExceptionHandler(InputErrorException.class)
  public ResponseEntity<?> handleException(InputErrorException exception) {
    return buildErrorResponse(exception.getMessage(), exception.getStatus());
  }

  @ExceptionHandler(TrivyConfigurationException.class)
  public ResponseEntity<?> handleException(TrivyConfigurationException exception) {
    final String errorMsg = String.join(", ", exception.getErrors());
    return buildErrorResponse(
        String.format("%s: exit code %d, %s",
            exception.getMessage(),
            exception.getExitCode(),
            errorMsg),
        exception.getStatus());
  }

  private ResponseEntity<?> buildErrorResponse(String message, HttpStatus httpStatus) {
    log.error("{}, status:{}", message, httpStatus);
    return ResponseEntity.status(httpStatus).body(message);
  }
}
