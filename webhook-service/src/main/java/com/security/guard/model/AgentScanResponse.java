package com.security.guard.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentScanResponse {

    @JsonProperty("scan_id")
    private String scanId;

    @JsonProperty("langsmith_run_id")
    private String langsmithRunId;

    private List<AgentFinding> findings;

    @JsonProperty("gate_decision")
    private String gateDecision;

    @JsonProperty("summary")
    private String summary;

    @JsonProperty("duration_ms")
    private Long durationMs;
}
