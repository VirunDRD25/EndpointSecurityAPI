namespace EndpointSecurityAPI.Dtos;

public record RiskWeightsDto(
    int FirewallDisabled,
    int DefenderDisabled,
    int RealtimeProtectionDisabled,
    int DefinitionsOutdated,
    int BitLockerOff,
    int UnapprovedUsbConnected,
    int UnauthorizedSoftware,
    int SuspiciousDownload,
    int UntrustedWifi,
    int WindowsUpdatesPending,
    int UnsupportedWindowsVersion,
    int BlacklistedExtension,
    int UnknownPublisherExtension,
    int DeveloperModeExtension,
    int SecurityExtensionRemoved,
    int DangerousExtensionPermissions
);

public record AlertThresholdsDto(
    int HighRiskThreshold,
    int StaleDeviceMinutes
);

public record SystemSettingsDto(
    List<string> ApprovedSoftware,
    List<string> TrustedWifiSsids,
    List<string> BlacklistedExtensions,
    List<string> RequiredSecurityExtensions,
    RiskWeightsDto RiskWeights,
    AlertThresholdsDto AlertThresholds,
    DateTime UpdatedUtc,
    string? UpdatedBy
);

public record UpdateSystemSettingsDto(
    List<string> ApprovedSoftware,
    List<string> TrustedWifiSsids,
    List<string> BlacklistedExtensions,
    List<string> RequiredSecurityExtensions,
    RiskWeightsDto RiskWeights,
    AlertThresholdsDto AlertThresholds
);

/// <summary>Shape returned to agents by GET /api/device/config — see DeviceConfigController.</summary>
public record DeviceConfigDto(
    List<string> ApprovedSoftware,
    List<string> TrustedWifiSsids,
    RiskWeightsDto RiskWeights
);
