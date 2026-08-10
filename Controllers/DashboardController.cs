using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using EndpointSecurityAPI.Entities;
using EndpointSecurityAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Controllers;

[ApiController]
[Route("api/dashboard")]
[Authorize] // admin JWT
public class DashboardController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly SystemSettingsProvider _settingsProvider;

    // Short, dashboard-friendly labels for each alert type — kept separate
    // from Alert.Message (which is a full sentence for the Alerts page) so
    // the Critical Alerts widget can show a tight bullet list like the mock.
    private static readonly Dictionary<AlertType, string> IssueLabels = new()
    {
        [AlertType.FirewallDisabled] = "Firewall Disabled",
        [AlertType.DefenderDisabled] = "Defender Disabled",
        [AlertType.UnauthorizedSoftware] = "Unknown Software Installed",
        [AlertType.SuspiciousDownload] = "Suspicious Download",
        [AlertType.UnknownUsbDevice] = "Unknown USB Device Connected",
        [AlertType.UntrustedWifi] = "Untrusted Wi-Fi Network",
        [AlertType.HighRiskScore] = "High Risk Score",
        [AlertType.DeviceOffline] = "Device Offline"
    };

    public DashboardController(AppDbContext db, SystemSettingsProvider settingsProvider)
    {
        _db = db;
        _settingsProvider = settingsProvider;
    }

    [HttpGet("summary")]
    public async Task<ActionResult<DashboardSummaryDto>> Summary()
    {
        var thresholds = await _settingsProvider.GetAlertThresholdsAsync();
        var onlineCutoff = DateTime.UtcNow.AddMinutes(-thresholds.StaleDeviceMinutes);

        var devices = await _db.Devices.Where(d => d.IsActive).ToListAsync();

        int total = devices.Count;
        int online = devices.Count(d => d.LastSeenUtc >= onlineCutoff);

        int low = 0, medium = 0, high = 0;
        foreach (var d in devices)
        {
            switch (RiskLevelHelper.Classify(d.CurrentRiskScore, thresholds.HighRiskThreshold))
            {
                case "High": high++; break;
                case "Medium": medium++; break;
                default: low++; break;
            }
        }

        double avgRisk = total == 0 ? 0 : devices.Average(d => d.CurrentRiskScore);
        int unresolvedAlerts = await _db.Alerts.CountAsync(a => !a.IsResolved);

        return Ok(new DashboardSummaryDto(total, online, total - online, low, medium, high, unresolvedAlerts, Math.Round(avgRisk, 1)));
    }

    /// <summary>
    /// Powers the dashboard's "Critical Alerts" widget: devices with at
    /// least one unresolved alert, ordered by risk score, each with a short
    /// bullet list of what's currently wrong.
    /// </summary>
    [HttpGet("critical-devices")]
    public async Task<ActionResult<List<CriticalDeviceDto>>> CriticalDevices([FromQuery] int take = 10)
    {
        var thresholds = await _settingsProvider.GetAlertThresholdsAsync();

        var devicesWithOpenAlerts = await _db.Alerts
            .Where(a => !a.IsResolved)
            .Include(a => a.Device)
            .Where(a => a.Device != null && a.Device.IsActive)
            .ToListAsync();

        var grouped = devicesWithOpenAlerts
            .GroupBy(a => a.Device!)
            .Select(g => new CriticalDeviceDto(
                g.Key.Id,
                g.Key.DeviceName,
                g.Key.Username,
                g.Key.Department,
                g.Key.CurrentRiskScore,
                RiskLevelHelper.Classify(g.Key.CurrentRiskScore, thresholds.HighRiskThreshold),
                g.Select(a => IssueLabels.GetValueOrDefault(a.Type, a.Type.ToString())).Distinct().ToList()
            ))
            .OrderByDescending(d => d.RiskScore)
            .Take(take)
            .ToList();

        return Ok(grouped);
    }
}
