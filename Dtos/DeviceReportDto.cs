using System.Text.Json.Serialization;

namespace EndpointSecurityAPI.Dtos;

/// <summary>
/// Mirrors EndpointSecurityAgent.Models.DeviceReport field-for-field
/// (including JSON property names) so the agent's JsonContent.Create(report)
/// binds here with no changes needed on either side. Keep these two files in
/// sync whenever the agent's model changes.
/// </summary>
public class DeviceReportDto
{
    [JsonPropertyName("deviceId")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("deviceName")]
    public string DeviceName { get; set; } = string.Empty;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("windowsVersion")]
    public string WindowsVersion { get; set; } = string.Empty;

    [JsonPropertyName("ipAddress")]
    public string IpAddress { get; set; } = string.Empty;

    [JsonPropertyName("macAddress")]
    public string MacAddress { get; set; } = string.Empty;

    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; set; } = string.Empty;

    [JsonPropertyName("lastSeenUtc")]
    public DateTime LastSeenUtc { get; set; }

    [JsonPropertyName("firewall")]
    public FirewallStatusDto Firewall { get; set; } = new();

    [JsonPropertyName("defender")]
    public DefenderStatusDto Defender { get; set; } = new();

    [JsonPropertyName("bitLocker")]
    public BitLockerStatusDto BitLocker { get; set; } = new();

    [JsonPropertyName("windowsUpdate")]
    public WindowsUpdateStatusDto WindowsUpdate { get; set; } = new();

    [JsonPropertyName("installedSoftware")]
    public List<string> InstalledSoftware { get; set; } = new();

    [JsonPropertyName("browserExtensions")]
    public List<BrowserExtensionDto> BrowserExtensions { get; set; } = new();

    [JsonPropertyName("missingRequiredSecurityExtensions")]
    public List<string> MissingRequiredSecurityExtensions { get; set; } = new();

    [JsonPropertyName("unauthorizedSoftware")]
    public List<string> UnauthorizedSoftware { get; set; } = new();

    [JsonPropertyName("recentDownloads")]
    public List<DownloadedFileInfoDto> RecentDownloads { get; set; } = new();

    [JsonPropertyName("usbEvents")]
    public List<UsbEventDto> UsbEvents { get; set; } = new();

    [JsonPropertyName("wifi")]
    public WifiStatusDto Wifi { get; set; } = new();

    [JsonPropertyName("riskScore")]
    public int RiskScore { get; set; }

    [JsonPropertyName("riskFactors")]
    public List<string> RiskFactors { get; set; } = new();
}

public class FirewallStatusDto
{
    [JsonPropertyName("domainEnabled")]
    public bool DomainEnabled { get; set; }

    [JsonPropertyName("privateEnabled")]
    public bool PrivateEnabled { get; set; }

    [JsonPropertyName("publicEnabled")]
    public bool PublicEnabled { get; set; }
}

public class DefenderStatusDto
{
    [JsonPropertyName("antivirusEnabled")]
    public bool AntivirusEnabled { get; set; }

    [JsonPropertyName("realTimeProtectionEnabled")]
    public bool RealTimeProtectionEnabled { get; set; }

    [JsonPropertyName("definitionsUpToDate")]
    public bool DefinitionsUpToDate { get; set; }

    [JsonPropertyName("definitionAgeDays")]
    public int DefinitionAgeDays { get; set; }

    /// <summary>"UpToDate" | "Outdated" | "Unknown" — added in the Phase 1 bugfix.</summary>
    [JsonPropertyName("definitionsStatus")]
    public string DefinitionsStatus { get; set; } = "Unknown";

    [JsonPropertyName("lastFullScanUtc")]
    public DateTime? LastFullScanUtc { get; set; }

    [JsonPropertyName("statusReadSuccessfully")]
    public bool StatusReadSuccessfully { get; set; }
}

public class BitLockerStatusDto
{
    [JsonPropertyName("systemDriveEncrypted")]
    public bool SystemDriveEncrypted { get; set; }

    [JsonPropertyName("protectionStatus")]
    public string ProtectionStatus { get; set; } = "Unknown";

    [JsonPropertyName("encryptionPercentage")]
    public int EncryptionPercentage { get; set; }
}

public class WindowsUpdateStatusDto
{
    [JsonPropertyName("lastInstalledUtc")]
    public DateTime? LastInstalledUtc { get; set; }

    [JsonPropertyName("pendingUpdateCount")]
    public int PendingUpdateCount { get; set; }

    [JsonPropertyName("isSupportedVersion")]
    public bool IsSupportedVersion { get; set; } = true;
}

public class DownloadedFileInfoDto
{
    [JsonPropertyName("fileName")]
    public string FileName { get; set; } = string.Empty;

    [JsonPropertyName("fullPath")]
    public string FullPath { get; set; } = string.Empty;

    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; } = string.Empty;

    [JsonPropertyName("isDigitallySigned")]
    public bool IsDigitallySigned { get; set; }

    [JsonPropertyName("publisher")]
    public string Publisher { get; set; } = "Unknown";

    [JsonPropertyName("fileType")]
    public string FileType { get; set; } = string.Empty;

    [JsonPropertyName("detectedUtc")]
    public DateTime DetectedUtc { get; set; }

    [JsonPropertyName("sourceFolder")]
    public string SourceFolder { get; set; } = string.Empty;

    [JsonPropertyName("isSuspicious")]
    public bool IsSuspicious { get; set; }
}

public class UsbEventDto
{
    [JsonPropertyName("deviceDescription")]
    public string DeviceDescription { get; set; } = string.Empty;

    [JsonPropertyName("driveLetter")]
    public string? DriveLetter { get; set; }

    [JsonPropertyName("serialNumber")]
    public string? SerialNumber { get; set; }

    [JsonPropertyName("insertedUtc")]
    public DateTime InsertedUtc { get; set; }

    [JsonPropertyName("eventType")]
    public string EventType { get; set; } = "Inserted";
}

public class WifiStatusDto
{
    [JsonPropertyName("connectedSsid")]
    public string? ConnectedSsid { get; set; }

    [JsonPropertyName("isTrusted")]
    public bool IsTrusted { get; set; }

    [JsonPropertyName("signalStrengthPercent")]
    public int SignalStrengthPercent { get; set; }
}

public class BrowserExtensionDto
{
    [JsonPropertyName("browser")]
    public string Browser { get; set; } = string.Empty;

    [JsonPropertyName("profile")]
    public string Profile { get; set; } = string.Empty;

    [JsonPropertyName("extensionId")]
    public string ExtensionId { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = "Unknown";

    [JsonPropertyName("publisher")]
    public string Publisher { get; set; } = "Unknown";

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; } = new();

    [JsonPropertyName("isEnabled")]
    public bool IsEnabled { get; set; } = true;

    [JsonPropertyName("isFromWebStore")]
    public bool IsFromWebStore { get; set; }

    [JsonPropertyName("isDeveloperMode")]
    public bool IsDeveloperMode { get; set; }

    [JsonPropertyName("isBlacklisted")]
    public bool IsBlacklisted { get; set; }

    [JsonPropertyName("hasDangerousPermissions")]
    public bool HasDangerousPermissions { get; set; }

    [JsonPropertyName("installedUtc")]
    public DateTime? InstalledUtc { get; set; }
}