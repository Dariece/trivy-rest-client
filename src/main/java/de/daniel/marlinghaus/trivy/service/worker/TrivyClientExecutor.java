package de.daniel.marlinghaus.trivy.service.worker;

import de.daniel.marlinghaus.trivy.configuration.property.TrivyProperties;
import de.daniel.marlinghaus.trivy.contoller.vo.CvssSeverity;
import de.daniel.marlinghaus.trivy.contoller.vo.ScanJob;
import de.daniel.marlinghaus.trivy.exception.TrivyConfigurationException;
import io.micrometer.core.instrument.util.IOUtils;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Execute trivy cli as process via cmd command
 */
@Component
@AllArgsConstructor
@Slf4j
public class TrivyClientExecutor {

  private final TrivyProperties properties;

  //TODO conditional on Property active-profile = local: zusätzliche parameter --debug und co

  /**
   * Execute trivy cli as sub-process via cmd command
   *
   * @param sbomFile input file
   * @param outFile  output file
   * @return InputStreamResource json scan report from trivy
   */
  public InputStreamResource executeForSbom(Path sbomFile, Path outFile, ScanJob job) {
    Process process;

    // Build trivy cli command
    //https://aquasecurity.github.io/trivy/v0.38/docs/references/cli/sbom/
    //only compatible with trivy > v0.38.0
    String command = String.format("%s/trivy sbom "
            + "--scanners vuln "
            + "--vuln-type library "
            + "--format json "
            + "--server \"%s\" "
            + "--exit-code 3 "
            + "--timeout %dm "
            + "%s"
            + "%s "
            + "-o %s"
        , properties.getBinDirectory(),
        properties.getHost(),
        properties.getProcessTimeout(),
        parseSeverityParam(job.getSeverities()),
        sbomFile,
        outFile);
    log.debug("Executing command: {}", command);

    try {
      process = Runtime.getRuntime().exec(command);

      if (!process.waitFor(properties.getProcessTimeout(), TimeUnit.MINUTES)) {
        //failure handling for process timeout
        log.debug("Try to kill process pid={}", process.pid());
        process.destroyForcibly();

        var message = String.format("Fatal error, trivy process timed out by %s minutes",
            properties.getProcessTimeout());
        log.debug(message);
        throw new RuntimeException(message);
      }

      int exitCode = process.exitValue();
      log.debug("Trivy cli exit code {}", exitCode);
      if (exitCode != 3 && exitCode != 0) {
        //failure handling on error exit code
        var errorList = handleStdout(process.getInputStream(), process.getErrorStream());
        throw new TrivyConfigurationException("Trivy failed to create a report", exitCode,
            errorList);
      }

      return new InputStreamResource(Files.newInputStream(outFile));

    } catch (FileNotFoundException e) {
      throw new RuntimeException(e.getMessage());

    } catch (IOException | InterruptedException e) {
      var message = String.format("Fatal error, command %s couldn't be executed", command);
      log.debug(e.getMessage());
      throw new RuntimeException(message, e);
    }
  }

  /**
   * Parse stdout to make it human-readable
   *
   * @param stdout standard output from process
   * @param stderr error output from process
   * @return List of error messages of trivy process
   * @throws IOException if output from process cannot be opened
   */
  private List<String> handleStdout(InputStream stdout, InputStream stderr) throws IOException {
//    logProcessStream(stdout, "stdout"); //use carefully on error to much output
    var errorOut = logProcessStream(stderr, "stderr");

    //manipulate stderr to get a list filtered by error messages
    return Arrays.stream(StringUtils.tokenizeToStringArray(errorOut, ";"))
        .filter(line -> line.contains("FATAL") || line.contains("ERROR"))
        .map(errorLine -> errorLine.substring(34).trim()).toList();
  }

  private String logProcessStream(InputStream processStream, String type) throws IOException {
    try {
      String std = IOUtils.toString(processStream, StandardCharsets.UTF_8).replace("\n", " ; ")
          .replace("\r", " ; ");

      if ("stdout".equals(type)) {
        log.debug("Trivy {}: {}", type, std);
      } else {
        log.error("Trivy {}: {}", type, std);
      }

      return std;
    } catch (Exception e) {
      var message = String.format("Trivy %s couldn't be opened: %s", type, e.getMessage());
      log.warn(message);
      throw new IOException(message);
    }
  }

  /**
   * Parse severity list to trivy cli comma separated format for param --severity
   *
   * @param severities severity list
   * @return trivy cli comma separated string format of severities
   */
  private String parseSeverityParam(List<CvssSeverity> severities) {
    var retVal = "";

    if (!severities.isEmpty()) {
      var severityStrings = severities.stream().map(Enum::name).toList();
      retVal = String.format("--severity %s ",
          severityStrings.size() > 1 ? StringUtils.collectionToCommaDelimitedString(severityStrings)
              : severityStrings.get(0));
    }

    return retVal;
  }
}
