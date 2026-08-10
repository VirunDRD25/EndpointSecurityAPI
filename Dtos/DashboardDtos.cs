namespace EndpointSecurityAPI.Dtos;

public record DeviceListItemDto(
    int Id,
    string HardwareDeviceId,
    string DeviceName,
    string Username,
    string? Department,
    string WindowsVersion,
    string IpAddress,
    DateTime LastSeenUtc,
    bool IsOnline,
    int CurrentRiskScore,
    string RiskLevel,
    int UnresolvedAlertCount
);

public record DeviceDetailDto(
    int Id,
    string HardwareDeviceId,
    string DeviceName,
    string Username,
    string? Department,
    string WindowsVersion,
    string IpAddress,
    string MacAddress,
    string SerialNumber,
    DateTime FirstEnrolledUtc,
    DateTime LastSeenUtc,
    bool IsOnline,
    int CurrentRiskScore,
    string RiskLevel,
    SecurityStatusSnapshotDto? LatestSnapshot,
    List<RiskHistoryPointDto> RiskHistory,
    List<string> InstalledSoftware,
    List<string> UnauthorizedSoftware,
    List<DownloadedFileInfoDto> RecentDownloads,
    List<UsbEventDto> RecentUsbEvents,
    List<BrowserExtensionSummaryDto> BrowserExtensions
);

public record BrowserExtensionSummaryDto(
    string Browser,
    string Profile,
    string ExtensionId,
    string Name,
    string Version,
    string Publisher,
    List<string> Permissions,
    bool IsEnabled,
    bool IsFromWebStore,
    bool IsDeveloperMode,
    bool IsBlacklisted,
    bool HasDangerousPermissions,
    DateTime? InstalledUtc
);

/// <summary>Admin-editable fields on a device — currently just Department (see Device.cs for why).</summary>
public record UpdateDeviceDto(string? Department);

public record SecurityStatusSnapshotDto(
    DateTime ReportedUtc,
    bool FirewallAllEnabled,
    bool DefenderAntivirusEnabled,
    bool DefenderRealTimeProtectionEnabled,
    string DefenderDefinitionsStatus,
    bool BitLockerEncrypted,
    int WindowsUpdatePendingCount,
    bool WindowsIsSupportedVersion,
    string? WifiSsid,
    bool WifiIsTrusted,
    int RiskScore,
    List<string> RiskFactors
);

public record RiskHistoryPointDto(DateTime ReportedUtc, int RiskScore);

public record DashboardSummaryDto(
    int TotalDevices,
    int OnlineDevices,
    int OfflineDevices,
    int LowRiskCount,
    int MediumRiskCount,
    int HighRiskCount,
    int UnresolvedAlerts,
    double AverageRiskScore
);

/// <summary>
/// One entry in the dashboard's "Critical Alerts" widget — a device with
/// unresolved high-severity issues, plus a short human-readable list of
/// what's wrong (derived from that device's unresolved Alerts, not the raw
/// risk-factor sentences, so the wording stays consistent with the Alerts page).
/// </summary>
public record CriticalDeviceDto(
    int DeviceId,
    string DeviceName,
    string Username,
    string? Department,
    int RiskScore,
    string RiskLevel,
    List<string> Issues
);

public record AlertDto(
    int Id,
    int DeviceId,
    string DeviceName,
    string Type,
    string Severity,
    string Message,
    DateTime CreatedUtc,
    bool IsResolved,
    DateTime? ResolvedUtc
);
