package de.daniel.marlinghaus.trivy.contoller.vo;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

/**
 * Value object of the job
 */
@Getter
@Setter
@AllArgsConstructor
public class ScanJob {

  /**
   * Name of application to scan
   */
  @NotBlank(message = "Name of application to scan is missing.")
  private String applicationName;

  /**
   * Scan format
   */
  @NotNull(message = "Scan format is missing.")
  private ScanFormat format;

  /**
   * Stage of dedicated deployment
   */
  @NotBlank(message = "Stage of dedicated deployment is missing.")
  private String stage;

  /**
   * Name of the dedicated pipelineRun
   */
  @Nullable
  private String pipelineRun;

  /**
   * Severity list that filters the trivy report output
   */
  @Nullable
  private List<CvssSeverity> severities;


}
