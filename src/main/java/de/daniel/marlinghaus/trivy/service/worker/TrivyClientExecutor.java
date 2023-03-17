package de.daniel.marlinghaus.trivy.service.worker;

import de.daniel.marlinghaus.trivy.configuration.property.TrivyProperties;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.stereotype.Component;

/**
 * Execute trivy cli as process via cmd command
 */
@Component
@AllArgsConstructor
@Slf4j
public class TrivyClientExecutor {

  private final TrivyProperties trivyProperties;

  /**
   * Execute trivy cli as process via cmd command
   *
   * @param sbomFile input file
   * @param outFile  output file
   * @return InputStreamResource json scan report from trivy
   */
  public InputStreamResource executeForSbom(Path sbomFile, Path outFile) {
    Process process;

    //Build trivy cli command
    //https://aquasecurity.github.io/trivy/v0.38/docs/references/cli/client/
    //TODO try cyclonedx format https://aquasecurity.github.io/trivy/v0.38/docs/sbom/cyclonedx/
    String command = String.format("%s/trivy sbom"
            + " --scurity-checks vuln "
            + "--format=json "
            + "--server %s"
            + "--exit-code 3 "
            + "%s "
            + "-o %s"
        , trivyProperties.getBinDirectory(), trivyProperties.host, sbomFile, outFile);
    log.debug("Executing command: {}" + command);

    try {
      process = Runtime.getRuntime().exec(command);

      if (process.waitFor(trivyProperties.getProcessTimeout(), TimeUnit.MINUTES)) {
        log.debug("Trivy cli exit code {}", process.exitValue());

        //TODO log depending on exit code 3=found security issue, 1=fail, 0=ok
        return new InputStreamResource(new FileInputStream(outFile.toFile()));
      } else {
        //failure handling for process timeout
        log.debug("Try to kill process pid={}", process.pid());
        process.destroyForcibly();

        var message = String.format("Fatal error, trivy process timed out by %s minutes",
            trivyProperties.getProcessTimeout());
        log.error(message);
        throw new RuntimeException(message);
      }
    } catch (IOException | InterruptedException e) {
      var message = String.format("Fatal error, command %s couldn't be executed", command);
      log.error(message);
      throw new RuntimeException(message, e);
    }
  }
}
