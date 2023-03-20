package de.daniel.marlinghaus.trivy.service;

import static de.daniel.marlinghaus.trivy.contoller.vo.ScanFormat.SBOM;

import de.daniel.marlinghaus.trivy.contoller.vo.ScanJob;
import de.daniel.marlinghaus.trivy.exception.InputErrorException;
import de.daniel.marlinghaus.trivy.service.worker.StorageWriter;
import de.daniel.marlinghaus.trivy.service.worker.TrivyClientExecutor;
import de.daniel.marlinghaus.trivy.service.worker.TrivyResultProcessor;
import java.io.IOException;
import java.nio.file.Path;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.MimeType;
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
  private final StorageWriter storageWriter;

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
    var contentType = scanObject.getContentType() != null ? scanObject.getContentType() : "";
    var format = job.getFormat();

    try {
      if (SBOM.equals(format) && MediaType.APPLICATION_JSON.isCompatibleWith(
          MimeType.valueOf(contentType))) { //Validate input content

        //Write scanObject to storage
        storageWriter.writeInputFile(job, scanObject.getInputStream());
        Path sbomFile = storageWriter.getActualInputFile();
        //Use trivy cli client to scan the object
        retVal = clientExecutor.executeForSbom(sbomFile, storageWriter.getActualOutputFile(), job);
        //Interpret the scan result
        retVal = trivyResultProcessor.processResult(
            retVal); //TODO filter entries with severity < HIGH, return own format

        log.info("Trivy scan report for {} SUCCESSFUL", sbomFile.getFileName().toString());
      } else {
        var message = String.format("Format %s with content type %s is not supported.", format,
            contentType);
        log.debug(message);
        throw new InputErrorException(message);
      }

      return retVal;
    } finally {
      //Cleanup after processing
      storageWriter.deleteDirectoryQuietly();
    }
  }
}
