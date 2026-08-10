namespace EndpointSecurityAPI.Entities;

/// <summary>
/// Current browser extension inventory per device — same upsert pattern as
/// InstalledSoftwareRecord (FirstSeenUtc/LastSeenUtc/CurrentlyInstalled)
/// so "new extension installed" and "extension removed" can both be
/// detected without the agent needing to diff anything itself.
/// </summary>
public class BrowserExtensionRecord
{
    public int Id { get; set; }

    public int DeviceId { get; set; }
    public Device? Device { get; set; }

    public string Browser { get; set; } = string.Empty;
    public string Profile { get; set; } = string.Empty;
    public string ExtensionId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = "Unknown";
    public string Publisher { get; set; } = "Unknown";

    /// <summary>List&lt;string&gt; stored as JSON — same pattern as SecurityStatusSnapshot.RiskFactorsJson.</summary>
    public string PermissionsJson { get; set; } = "[]";

    public bool IsEnabled { get; set; }
    public bool IsFromWebStore { get; set; }
    public bool IsDeveloperMode { get; set; }
    public bool IsBlacklisted { get; set; }
    public bool HasDangerousPermissions { get; set; }

    public DateTime? InstalledUtc { get; set; }
    public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
    public bool CurrentlyInstalled { get; set; } = true;
}