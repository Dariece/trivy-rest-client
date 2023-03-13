package de.daniel.marlinghaus.trivy.service;

import static de.daniel.marlinghaus.trivy.contoller.vo.ScanFormat.SBOM;

import de.daniel.marlinghaus.trivy.configuration.property.TrivyProperties;
import de.daniel.marlinghaus.trivy.contoller.vo.ScanJob;
import de.daniel.marlinghaus.trivy.exception.InputErrorException;
import de.daniel.marlinghaus.trivy.service.worker.TrivyClientExecutor;
import de.daniel.marlinghaus.trivy.service.worker.TrivyResultProcessor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.InputStreamResource;
import org.springframework.stereotype.Component;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StreamUtils;
import org.springframework.web.multipart.MultipartFile;

/**
 * orchestrate the scan process by trivy
 */
@Component
@AllArgsConstructor
@Slf4j
public class TrivyClientService {

  private final TrivyClientExecutor clientExecutor;
  private final TrivyResultProcessor trivyResultProcessor;
  private final TrivyProperties trivyProperties;

  /**
   * orchestrate the scan process by trivy
   *
   * @param scanObject object to by scanned by trivy
   * @param job        job details for processing
   * @return scan report by trivy
   * @throws InputErrorException invalid input by caller
   * @throws IOException         unable to write scanObject to storage
   */
  public InputStreamResource scan(MultipartFile scanObject, ScanJob job)
      throws InputErrorException, IOException {
    InputStreamResource retVal;
    var contentType = scanObject.getContentType();
    var format = job.getFormat();
    var tmpDir = trivyProperties.getTmpDirectory();

    try {
      if (SBOM.equals(format) && "json".equalsIgnoreCase(contentType)) {
        //Generate fileName
        String fileName = String.format("%s-%s-%s", job.getApplicationName(), job.getStage(),
            StringUtils.isNoneBlank(job.getPipelineRun())
                ? job.getPipelineRun() : UUID.randomUUID().toString());
        var sbomFile = tmpDir.resolve(fileName + "-sbom.json");
        var outFile = tmpDir.resolve(fileName + ".json");

        //Write scanObject to storage
        try (var outputStream = Files.newOutputStream(sbomFile)) {
          StreamUtils.copy(scanObject.getInputStream(), outputStream);
        }

        //Use trivy cli client to scan the object
        retVal = clientExecutor.executeForSbom(sbomFile, outFile);
        //Interpret the scan result
        retVal = trivyResultProcessor.processResult(
            retVal); //TODO filter entries with severity < HIGH, return own format

        log.info("Trivy scan report for {} SUCCESSFUL", sbomFile.getFileName().toString());
      } else {
        log.error("Processing failed, wrong format {} or type {}", format, contentType);
        throw new InputErrorException(
            String.format("Format %s with content type %s is not supported.", format, contentType));
      }

      return retVal;
    } finally {
      //Cleanup after processing
      deleteDirectoryQuietly(tmpDir);
    }
  }

  private void deleteDirectoryQuietly(final Path workingDirectory) {
    try {
      FileSystemUtils.deleteRecursively(workingDirectory);
    } catch (IOException e) {
      log.warn("deleteDirectoryQuietly failed ", e);
    }
  }
}
