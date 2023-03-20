package de.daniel.marlinghaus.trivy.contoller;

import de.daniel.marlinghaus.trivy.contoller.vo.ScanJob;
import de.daniel.marlinghaus.trivy.service.TrivyClientService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@CrossOrigin
@AllArgsConstructor
@RequestMapping("/trivy")
@RestController
@Slf4j
public class TrivyClientController {

  private final TrivyClientService clientService;

  @PostMapping(
      value = "scan",
      consumes = MediaType.MULTIPART_FORM_DATA_VALUE
      , produces = MediaType.APPLICATION_OCTET_STREAM_VALUE
  )
  public ResponseEntity<?> getReport(
      @RequestPart("scanJob") @Valid final ScanJob scanJob,
      @RequestPart("scanObject") @NotNull(message = "Scanable object is missing.") final MultipartFile scanObject)
      throws Exception {

    log.info("request for application {}: format={}; stage{}; pipelineRun={}",
        scanJob.getApplicationName(), scanJob.getFormat().name().toLowerCase(), scanJob.getStage(),
        scanJob.getPipelineRun());

    var reportResult = clientService.scan(scanObject, scanJob);

    return ResponseEntity.ok().body(reportResult);
  }

  @PostMapping(
      value = "mock",
      consumes = MediaType.MULTIPART_FORM_DATA_VALUE
      , produces = MediaType.APPLICATION_OCTET_STREAM_VALUE
  )
  public ResponseEntity<?> getMockReport(
      @RequestPart("scanJob") @Valid final ScanJob scanJob,
      @RequestPart("scanObject") @NotNull(message = "Scanable object is missing.") final MultipartFile scanObject)
      throws Exception {

    log.info("MOCK! request for application {}: format={}; stage{}; pipelineRun={}",
        scanJob.getApplicationName(), scanJob.getFormat().name().toLowerCase(), scanJob.getStage(),
        scanJob.getPipelineRun());

    return ResponseEntity.ok().body(new ClassPathResource(
        "classpath:mocks/vulnerability-sbom-test-local-bec7c176-06db-4d76-8247-6686b73d761d-trivy-report.json"));
  }
}
