namespace EndpointSecurityAPI.Entities;

/// <summary>
/// One row per report received from the agent. This is the historical
/// timeline used for the risk-score-over-time chart and audit trail.
/// Kept intentionally denormalized/flat (rather than one table per check)
/// since it's always read/written as a single unit per report.
/// </summary>
public class SecurityStatusSnapshot
{
    public int Id { get; set; }

    public int DeviceId { get; set; }
    public Device? Device { get; set; }

    public DateTime ReportedUtc { get; set; } = DateTime.UtcNow;

    // --- Firewall ---
    public bool FirewallDomainEnabled { get; set; }
    public bool FirewallPrivateEnabled { get; set; }
    public bool FirewallPublicEnabled { get; set; }

    // --- Defender ---
    public bool DefenderAntivirusEnabled { get; set; }
    public bool DefenderRealTimeProtectionEnabled { get; set; }
    /// <summary>"UpToDate" | "Outdated" | "Unknown" — mirrors the agent's Phase 1 bugfix.</summary>
    public string DefenderDefinitionsStatus { get; set; } = "Unknown";
    public int DefenderDefinitionAgeDays { get; set; } = -1;
    public bool DefenderStatusReadSuccessfully { get; set; }

    // --- BitLocker ---
    public bool BitLockerEncrypted { get; set; }
    public string BitLockerProtectionStatus { get; set; } = "Unknown";
    public int BitLockerEncryptionPercentage { get; set; }

    // --- Windows Update ---
    public DateTime? WindowsUpdateLastInstalledUtc { get; set; }
    public int WindowsUpdatePendingCount { get; set; }
    public bool WindowsIsSupportedVersion { get; set; } = true;

    // --- Wi-Fi ---
    public string? WifiSsid { get; set; }
    public bool WifiIsTrusted { get; set; }
    public int WifiSignalStrengthPercent { get; set; }

    // --- Risk ---
    public int RiskScore { get; set; }

    /// <summary>Human-readable risk reasons, stored as a JSON string array.</summary>
    public string RiskFactorsJson { get; set; } = "[]";

    /// <summary>Unauthorized software names detected in this report, stored as JSON string array.</summary>
    public string UnauthorizedSoftwareJson { get; set; } = "[]";
}
