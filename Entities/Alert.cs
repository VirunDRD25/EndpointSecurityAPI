namespace EndpointSecurityAPI.Entities;

public enum AlertSeverity
{
    Low,
    Medium,
    High,
    Critical
}

public enum AlertType
{
    FirewallDisabled,
    DefenderDisabled,
    BitLockerOff,
    UnauthorizedSoftware,
    SuspiciousDownload,
    UnknownUsbDevice,
    UntrustedWifi,
    HighRiskScore,
    DeviceOffline,
    BlacklistedExtension,
    DeveloperModeExtension,
    SecurityExtensionRemoved,
    NewBrowserExtension
}

public class Alert
{
    public int Id { get; set; }

    public int DeviceId { get; set; }
    public Device? Device { get; set; }

    public AlertType Type { get; set; }
    public AlertSeverity Severity { get; set; }
    public string Message { get; set; } = string.Empty;

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public bool IsResolved { get; set; }
    public DateTime? ResolvedUtc { get; set; }
    public string? ResolvedBy { get; set; }

    /// <summary>Set once a notification (e.g. email) has been dispatched for this alert — see Phase 5.</summary>
    public bool NotificationSent { get; set; }
}
