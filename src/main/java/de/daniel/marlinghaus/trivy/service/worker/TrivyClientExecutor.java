package de.daniel.marlinghaus.trivy.service.worker;

import de.daniel.marlinghaus.trivy.configuration.property.TrivyProperties;
import io.micrometer.core.instrument.util.IOUtils;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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

    // Build trivy cli command
    //https://aquasecurity.github.io/trivy/v0.38/docs/references/cli/sbom/
    //filter severity only HIGH,CRITICAL --severity HIGH,CRITICAL
    String command = String.format("%s/trivy sbom"
//            + " --scurity-checks vuln "
            + "--format cyclonedx "
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
        handleStdout(process.getInputStream(), process.getErrorStream());

        //TODO log depending on exit code 3=found security issue, 1=fail, 0=ok
        return new InputStreamResource(new FileInputStream(outFile.toFile()));
      } else {
        //failure handling for process timeout
        log.debug("Try to kill process pid={}", process.pid());
        process.destroyForcibly();

        var message = String.format("Fatal error, trivy process timed out by %s minutes",
            trivyProperties.getProcessTimeout());
        log.debug(message);
        throw new RuntimeException(message);
      }
    } catch (FileNotFoundException e) {
      throw new RuntimeException(e.getMessage());
    } catch (IOException | InterruptedException e) {
      var message = String.format("Fatal error, command %s couldn't be executed", command);
      log.debug(e.getMessage());
      throw new RuntimeException(message, e);
    }
  }

  private void handleStdout(InputStream stdout, InputStream stderr){
    logProcessStream(stdout, "stdout");
    logProcessStream(stderr, "stderr");
  }

  private void logProcessStream(InputStream processStream, String type){
    try {
      String stderr = IOUtils.toString(processStream, StandardCharsets.UTF_8);
      log.error("Trivy {}: {}", type, stderr.replace("\n", " ; ").replace("\r", " ; "));
    } catch (Exception e) {
      log.warn("Trivy {} couldn't be opened: {}", type, e.getMessage());
    }
  }
}
