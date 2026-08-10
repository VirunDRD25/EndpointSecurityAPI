using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using EndpointSecurityAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Services;

/// <summary>
/// Turns report findings into Alert rows for the dashboard. Kept separate
/// from ReportIngestionService (single responsibility) and separate from
/// notification delivery (Phase 5 will add an EmailNotificationService that
/// watches for NotificationSent == false and sends/marks them).
/// </summary>
public class AlertService
{
    private readonly AppDbContext _db;
    private readonly ILogger<AlertService> _logger;
    private readonly SystemSettingsProvider _settingsProvider;

    public AlertService(AppDbContext db, ILogger<AlertService> logger, SystemSettingsProvider settingsProvider)
    {
        _db = db;
        _logger = logger;
        _settingsProvider = settingsProvider;
    }

    public async Task EvaluateAndCreateAlertsAsync(Device device, DeviceReportDto report, CancellationToken ct, List<string>? newlySeenExtensionNames = null)
{
    var newAlerts = new List<Alert>();

    if (!report.Firewall.DomainEnabled || !report.Firewall.PrivateEnabled || !report.Firewall.PublicEnabled)
        newAlerts.Add(BuildAlert(device, AlertType.FirewallDisabled, AlertSeverity.High,
            "Windows Firewall is disabled on one or more network profiles."));

    if (report.Defender.StatusReadSuccessfully && !report.Defender.AntivirusEnabled)
        newAlerts.Add(BuildAlert(device, AlertType.DefenderDisabled, AlertSeverity.Critical,
            "Microsoft Defender antivirus is disabled."));

    if (report.UnauthorizedSoftware.Count > 0)
        newAlerts.Add(BuildAlert(device, AlertType.UnauthorizedSoftware, AlertSeverity.Critical,
            $"Unauthorized software detected: {string.Join(", ", report.UnauthorizedSoftware)}"));

    foreach (var file in report.RecentDownloads.Where(f => f.IsSuspicious))
        newAlerts.Add(BuildAlert(device, AlertType.SuspiciousDownload, AlertSeverity.High,
            $"Unsigned/suspicious file downloaded: {file.FileName} (SHA-256: {file.Sha256[..Math.Min(12, file.Sha256.Length)]}...)"));

    foreach (var usb in report.UsbEvents.Where(u => u.EventType == "Inserted"))
        newAlerts.Add(BuildAlert(device, AlertType.UnknownUsbDevice, AlertSeverity.Low,
            $"USB storage device connected: {usb.DeviceDescription} ({usb.DriveLetter})"));

    if (report.Wifi.ConnectedSsid != null && !report.Wifi.IsTrusted)
        newAlerts.Add(BuildAlert(device, AlertType.UntrustedWifi, AlertSeverity.Medium,
            $"Connected to untrusted Wi-Fi network: {report.Wifi.ConnectedSsid}"));

    if (report.BrowserExtensions.Any(e => e.IsBlacklisted))
    {
        var names = string.Join(", ", report.BrowserExtensions
            .Where(e => e.IsBlacklisted).Select(e => e.Name).Distinct());
        newAlerts.Add(BuildAlert(device, AlertType.BlacklistedExtension, AlertSeverity.High,
            $"Blacklisted browser extension detected: {names}"));
    }

    if (report.BrowserExtensions.Any(e => e.IsDeveloperMode))
    {
        var names = string.Join(", ", report.BrowserExtensions
            .Where(e => e.IsDeveloperMode).Select(e => e.Name).Distinct());
        newAlerts.Add(BuildAlert(device, AlertType.DeveloperModeExtension, AlertSeverity.High,
            $"Developer-mode (unpacked) browser extension detected: {names}"));
    }

    if (report.MissingRequiredSecurityExtensions.Count > 0)
        newAlerts.Add(BuildAlert(device, AlertType.SecurityExtensionRemoved, AlertSeverity.High,
            $"Required security extension(s) missing: {string.Join(", ", report.MissingRequiredSecurityExtensions)}"));

    if (newlySeenExtensionNames is { Count: > 0 })
        newAlerts.Add(BuildAlert(device, AlertType.NewBrowserExtension, AlertSeverity.Medium,
            $"New browser extension(s) installed: {string.Join(", ", newlySeenExtensionNames)}"));

    // --- HighRiskScore: handled separately so we can UPDATE the message
    // on an existing open alert (threshold value in the message changes
    // when admin edits Configuration) instead of just skipping it via
    // the de-dupe check and showing a stale threshold forever.
    var thresholds = await _settingsProvider.GetAlertThresholdsAsync(ct);
    int highRiskThreshold = thresholds.HighRiskThreshold;

    var existingHighRisk = await _db.Alerts.FirstOrDefaultAsync(a =>
        a.DeviceId == device.Id &&
        a.Type == AlertType.HighRiskScore &&
        !a.IsResolved, ct);

    if (report.RiskScore >= highRiskThreshold)
    {
        string message = $"Device risk score reached {report.RiskScore} (threshold: {highRiskThreshold}).";
        if (existingHighRisk is not null)
        {
            // Update message in place so the threshold number stays current.
            existingHighRisk.Message = message;
        }
        else
        {
            newAlerts.Add(BuildAlert(device, AlertType.HighRiskScore, AlertSeverity.Critical, message));
        }
    }
    else if (existingHighRisk is not null)
    {
        // Score dropped below threshold — auto-resolve the alert.
        existingHighRisk.IsResolved = true;
        existingHighRisk.ResolvedUtc = DateTime.UtcNow;
        existingHighRisk.ResolvedBy = "system (risk score dropped below threshold)";
    }

    if (newAlerts.Count == 0 && existingHighRisk is null) return;

    // De-dupe: skip alert types that already have an open alert,
    // EXCEPT HighRiskScore which is handled above.
    var openTypes = await _db.Alerts
        .Where(a => a.DeviceId == device.Id && !a.IsResolved && a.Type != AlertType.HighRiskScore)
        .Select(a => a.Type)
        .ToListAsync(ct);

    foreach (var alert in newAlerts)
    {
        if (openTypes.Contains(alert.Type)) continue;
        _db.Alerts.Add(alert);
    }

    await _db.SaveChangesAsync(ct);
}

    /// <summary>Called when a device hasn't reported in for longer than the configured window — see StaleDeviceCheckService.</summary>
    public async Task CreateOfflineAlertIfNeededAsync(Device device, CancellationToken ct)
    {
        bool alreadyOpen = await _db.Alerts.AnyAsync(a =>
            a.DeviceId == device.Id && a.Type == AlertType.DeviceOffline && !a.IsResolved, ct);

        if (alreadyOpen) return;

        _db.Alerts.Add(BuildAlert(device, AlertType.DeviceOffline, AlertSeverity.Medium,
            $"Device has not reported in since {device.LastSeenUtc:u}."));

        await _db.SaveChangesAsync(ct);
    }

    private static Alert BuildAlert(Device device, AlertType type, AlertSeverity severity, string message) => new()
    {
        DeviceId = device.Id,
        Type = type,
        Severity = severity,
        Message = message,
        CreatedUtc = DateTime.UtcNow
    };
}
