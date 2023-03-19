package de.daniel.marlinghaus.trivy.service.worker;

import static java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;

import de.daniel.marlinghaus.trivy.configuration.property.TrivyProperties;
import de.daniel.marlinghaus.trivy.contoller.vo.ScanJob;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StreamUtils;

/**
 * Responsable for IO transaction to storage. Call writeInputFile to overwrite fileName.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class StorageWriter {

  private final TrivyProperties trivyProperties;
  private Path tmpDir;
  private String fileName;

  /**
   * Initialize temp work dir before request to speed up processing
   *
   * @throws IOException couldn't create temp dir
   */
  @PostConstruct
  private void setUp() throws IOException {
    tmpDir = trivyProperties.getTmpDirectory();

    if (Files.notExists(tmpDir)) {
      //Todo use Files.createTempDirectory to remove dir after graceful shutdown automatically
      Files.createDirectory(trivyProperties.getTmpDirectory(),
          PosixFilePermissions.asFileAttribute(EnumSet.of(OWNER_READ, OWNER_WRITE, OWNER_EXECUTE, OTHERS_WRITE)));
    }
  }

  /**
   * Writes input file as inputStream with filename schema for incomming scan job to storage.
   *
   * @param job ScanJob
   */
  public void writeInputFile(ScanJob job, InputStream content) {
    //Generate fileName
    fileName = String.format("%s-%s-%s", job.getApplicationName(), job.getStage(),
        StringUtils.isNoneBlank(job.getPipelineRun())
            ? job.getPipelineRun() : UUID.randomUUID().toString());

    var sbomFile = tmpDir.resolve(fileName + "-sbom.json");

    //Write content to storage
    try (var outputStream = Files.newOutputStream(sbomFile)) {
      StreamUtils.copy(content, outputStream);
    } catch (IOException e) {
      var message = String.format("Couldn't write input file %s to storage.", e.getMessage());
      log.debug(e.fillInStackTrace().getMessage());
      throw new RuntimeException(message, e);
    }
  }

  /**
   * @return path of inputFile for actual generated fileName
   */
  public Path getActualInputFile() {
    return tmpDir.resolve(fileName + "-sbom.json");
  }

  /**
   * @return path of outputFile for actual generated fileName
   */
  public Path getActualOutputFile() {
    return tmpDir.resolve(fileName + "-trivy-report.json");
  }

  /**
   * Try to delete tmpDir without application crash on failure.
   */
  public void deleteDirectoryQuietly() {
    try {
      FileSystemUtils.deleteRecursively(tmpDir);
      //Restore tmpDir after Cleanup
      setUp();
    } catch (IOException e) {
      log.warn("deleteDirectoryQuietly failed ", e);
    }
  }
}
