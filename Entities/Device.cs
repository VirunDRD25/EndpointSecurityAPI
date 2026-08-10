namespace EndpointSecurityAPI.Entities;

/// <summary>
/// One row per physical device. Keyed by HardwareDeviceId, which is the
/// motherboard/BIOS UUID the agent sends as "deviceId" — stable across
/// agent reinstalls, unlike computer name (which can be renamed).
/// </summary>
public class Device
{
    public int Id { get; set; }

    /// <summary>Hardware UUID from the agent (Win32_ComputerSystemProduct.UUID). Unique.</summary>
    public string HardwareDeviceId { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string WindowsVersion { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>
    /// Not reported by the agent (it has no way to know org structure) —
    /// set by an admin from the dashboard's device detail page via
    /// PATCH /api/devices/{id}. Null/blank shows as "Unassigned" in the UI.
    /// </summary>
    public string? Department { get; set; }

    public DateTime FirstEnrolledUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;

    /// <summary>Denormalized copy of the most recent report's score, for fast dashboard listing.</summary>
    public int CurrentRiskScore { get; set; }

    /// <summary>Which enrollment token this device first registered with (for audit trail).</summary>
    public int? EnrolledViaTokenId { get; set; }
    public EnrollmentToken? EnrolledViaToken { get; set; }

    public bool IsActive { get; set; } = true;

    public ICollection<SecurityStatusSnapshot> Snapshots { get; set; } = new List<SecurityStatusSnapshot>();
    public ICollection<InstalledSoftwareRecord> InstalledSoftware { get; set; } = new List<InstalledSoftwareRecord>();
    public ICollection<DownloadEvent> DownloadEvents { get; set; } = new List<DownloadEvent>();
    public ICollection<UsbEventRecord> UsbEvents { get; set; } = new List<UsbEventRecord>();
    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
}
