namespace EndpointSecurityAPI.Entities;

/// <summary>
/// Singleton settings row (always Id = 1) holding everything the Phase 4
/// dashboard's Configuration page manages. Stored as JSON columns since
/// these are variable-length lists/maps edited as a unit, not queried
/// individually.
///
/// NOTE: as of this write-up, only the Phase 2 API reads AlertThresholds
/// (for HighRiskThreshold / StaleDeviceMinutes — see AlertService and
/// StaleDeviceCheckService, which currently read from appsettings.json and
/// will need a small follow-up change to read from here instead).
/// ApprovedSoftware, TrustedWifiSsids, and RiskWeights are currently only
/// consumed locally by the Phase 1 agent's own appsettings.json /
/// ApprovedSoftware.json. Exposing GET /api/device/config (see
/// DeviceConfigController) lets the agent pull this centrally instead —
/// wiring the agent to actually call it is a follow-up Phase 1 change.
/// </summary>
public class SystemSettings
{
    public int Id { get; set; } = 1;

    public string ApprovedSoftwareJson { get; set; } = "[]";
    public string TrustedWifiSsidsJson { get; set; } = "[]";
    public string BlacklistedExtensionsJson { get; set; } = "[]";
    public string RequiredSecurityExtensionsJson { get; set; } = "[]";
    public string RiskWeightsJson { get; set; } = "{}";
    public string AlertThresholdsJson { get; set; } = "{}";

    public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
    public string? UpdatedBy { get; set; }
}
