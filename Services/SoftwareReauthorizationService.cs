using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Services;

/// <summary>
/// Runs whenever the Configuration page's Approved Software list is saved.
/// Re-evaluates every currently-installed software record across the
/// entire fleet against the new list, and auto-resolves any open
/// "Unauthorized Software" alert for a device that no longer has any
/// unauthorized software installed — so an admin approving something
/// (e.g. Zoom Workplace) fixes it everywhere immediately, not just for
/// future reports.
/// </summary>
public class SoftwareReauthorizationService
{
    private readonly AppDbContext _db;
    private readonly ILogger<SoftwareReauthorizationService> _logger;

    public SoftwareReauthorizationService(AppDbContext db, ILogger<SoftwareReauthorizationService> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task ReevaluateAllDevicesAsync(List<string> approvedSoftware, CancellationToken ct = default)
    {
        var currentlyInstalled = await _db.InstalledSoftware
            .Where(s => s.CurrentlyInstalled)
            .ToListAsync(ct);

        int changed = 0;
        foreach (var record in currentlyInstalled)
        {
            bool shouldBeUnauthorized = approvedSoftware.Count > 0 &&
                !SoftwareAuthorizationHelper.IsApproved(record.SoftwareName, approvedSoftware);

            if (record.IsUnauthorized != shouldBeUnauthorized)
            {
                record.IsUnauthorized = shouldBeUnauthorized;
                changed++;
            }
        }

        if (changed > 0) await _db.SaveChangesAsync(ct);
        _logger.LogInformation("Software re-authorization: {Changed} record(s) updated across the fleet.", changed);

        // Auto-resolve UnauthorizedSoftware alerts for devices that no longer have anything flagged.
        var deviceIdsStillUnauthorized = await _db.InstalledSoftware
            .Where(s => s.CurrentlyInstalled && s.IsUnauthorized)
            .Select(s => s.DeviceId)
            .Distinct()
            .ToListAsync(ct);

        var openAlerts = await _db.Alerts
            .Where(a => a.Type == AlertType.UnauthorizedSoftware && !a.IsResolved)
            .ToListAsync(ct);

        int resolvedCount = 0;
        foreach (var alert in openAlerts)
        {
            if (!deviceIdsStillUnauthorized.Contains(alert.DeviceId))
            {
                alert.IsResolved = true;
                alert.ResolvedUtc = DateTime.UtcNow;
                alert.ResolvedBy = "system (approved software list updated)";
                resolvedCount++;
            }
        }

        if (resolvedCount > 0) await _db.SaveChangesAsync(ct);
        _logger.LogInformation("Auto-resolved {Count} Unauthorized Software alert(s) after settings update.", resolvedCount);
    }
}