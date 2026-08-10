using EndpointSecurityAPI.Data;
using Microsoft.EntityFrameworkCore;
using EndpointSecurityAPI.Dtos;

namespace EndpointSecurityAPI.Services;

/// <summary>
/// Retroactively recomputes the CurrentRiskScore on every active Device
/// using the latest snapshot for that device and the newly-saved weights.
/// Called immediately after the Configuration page saves new risk weights,
/// so the dashboard reflects the change without waiting for every agent's
/// next 5-minute report cycle.
/// Note: SecurityStatusSnapshot.RiskScore (the history chart data) is NOT
/// retroactively changed — those are historical point-in-time records.
/// Only Device.CurrentRiskScore (the live dashboard value) is updated.
/// </summary>
public class RiskScoreRecomputeService
{
    private readonly AppDbContext _db;
    private readonly ILogger<RiskScoreRecomputeService> _logger;

    public RiskScoreRecomputeService(AppDbContext db, ILogger<RiskScoreRecomputeService> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task RecomputeAllAsync(RiskWeightsDto weights, CancellationToken ct = default)
    {
        var devices = await _db.Devices
            .Where(d => d.IsActive)
            .ToListAsync(ct);

        int updated = 0;

        foreach (var device in devices)
        {
            // Get the latest snapshot for this device — this is the most
            // recent set of check results the agent reported.
            var latestSnapshot = await _db.SecurityStatusSnapshots
                .Where(s => s.DeviceId == device.Id)
                .OrderByDescending(s => s.ReportedUtc)
                .FirstOrDefaultAsync(ct);

            if (latestSnapshot is null) continue;

            // Reconstruct a minimal DeviceReportDto from the snapshot so
            // RiskScoreServerCalculator can work with it — we only need the
            // fields that affect the score, not downloads/USB/extensions
            // (those are stored separately and we'd need extra queries).
            // For simplicity we use the snapshot's stored risk factors and
            // recompute only from what the snapshot captured.
            var newScore = RecomputeFromSnapshot(latestSnapshot, weights);

            if (device.CurrentRiskScore != newScore)
            {
                device.CurrentRiskScore = newScore;
                updated++;
            }
        }

        if (updated > 0)
        {
            await _db.SaveChangesAsync(ct);
            _logger.LogInformation("Risk score recompute: {Count} device(s) updated after weight change.", updated);
        }
    }

    private static int RecomputeFromSnapshot(Entities.SecurityStatusSnapshot s, RiskWeightsDto w)
    {
        int score = 0;

        bool firewallOff = !s.FirewallDomainEnabled || !s.FirewallPrivateEnabled || !s.FirewallPublicEnabled;
        if (firewallOff) score += w.FirewallDisabled;

        if (s.DefenderStatusReadSuccessfully)
        {
            if (!s.DefenderAntivirusEnabled) score += w.DefenderDisabled;
            else if (!s.DefenderRealTimeProtectionEnabled) score += w.RealtimeProtectionDisabled;
            if (s.DefenderDefinitionsStatus == "Outdated") score += w.DefinitionsOutdated;
        }

        if (!s.BitLockerEncrypted) score += w.BitLockerOff;
        if (s.WindowsUpdatePendingCount > 0) score += w.WindowsUpdatesPending;
        if (!s.WindowsIsSupportedVersion) score += w.UnsupportedWindowsVersion;
        if (!s.WifiIsTrusted && s.WifiSsid != null) score += w.UntrustedWifi;

        // UnauthorizedSoftware — stored as JSON in the snapshot
        try
        {
            var unauthorized = System.Text.Json.JsonSerializer
                .Deserialize<List<string>>(s.UnauthorizedSoftwareJson);
            if (unauthorized?.Count > 0) score += w.UnauthorizedSoftware;
        }
        catch { }

        // Browser extension and download/USB risk factors are stored in the
        // snapshot's RiskFactorsJson text — check for their presence by
        // reading the saved factor descriptions rather than re-querying
        // separate tables, to keep this method fast (no extra DB calls).
        try
        {
            var factors = System.Text.Json.JsonSerializer
                .Deserialize<List<string>>(s.RiskFactorsJson) ?? new();

            bool hasBlacklisted = factors.Any(f => f.Contains("Blacklisted browser extension", StringComparison.OrdinalIgnoreCase));
            bool hasDevMode = factors.Any(f => f.Contains("Developer-mode", StringComparison.OrdinalIgnoreCase));
            bool hasUnknownPub = factors.Any(f => f.Contains("unknown publisher", StringComparison.OrdinalIgnoreCase));
            bool hasDangerousPerms = factors.Any(f => f.Contains("dangerous permissions", StringComparison.OrdinalIgnoreCase));
            bool hasMissingRequired = factors.Any(f => f.Contains("Required security extension", StringComparison.OrdinalIgnoreCase));
            bool hasSuspiciousDownload = factors.Any(f => f.Contains("suspicious executable", StringComparison.OrdinalIgnoreCase));
            bool hasUsb = factors.Any(f => f.Contains("USB storage device", StringComparison.OrdinalIgnoreCase));

            if (hasBlacklisted) score += w.BlacklistedExtension;
            if (hasDevMode) score += w.DeveloperModeExtension;
            if (hasUnknownPub) score += w.UnknownPublisherExtension;
            if (hasDangerousPerms) score += w.DangerousExtensionPermissions;
            if (hasMissingRequired) score += w.SecurityExtensionRemoved;
            if (hasSuspiciousDownload) score += w.SuspiciousDownload;
            if (hasUsb) score += w.UnapprovedUsbConnected;
        }
        catch { }

        return Math.Min(score, 100);
    }
}