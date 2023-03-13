package de.daniel.marlinghaus.trivy.contoller;

import de.daniel.marlinghaus.trivy.contoller.vo.ScanJob;
import de.daniel.marlinghaus.trivy.service.TrivyClientService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@CrossOrigin // So that javascript can be hosted elsewhere
@AllArgsConstructor
@RequestMapping("/trivy")
@RestController
@Slf4j
public class TrivyClientController {

  private final TrivyClientService clientService;

  @PostMapping(
      value = "scan",
      consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<?> getReport(
      @RequestPart("job") @Valid final ScanJob job,
      @RequestPart("sbom") @NotNull(message = "Scanable object is missing.") final MultipartFile scanObject)
      throws Exception {

    log.info("request for application {}: format={}; stage{}; pipelineRun={}",
        job.getApplicationName(), job.getFormat().name().toLowerCase(), job.getStage(),
        job.getPipelineRun());

    var reportResult = clientService.scan(scanObject, job);

    return ResponseEntity.ok().body(reportResult);
  }
}
