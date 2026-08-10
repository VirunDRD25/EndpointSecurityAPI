using System.Text.Json;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using EndpointSecurityAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using EndpointSecurityAPI.Entities;

namespace EndpointSecurityAPI.Controllers;

[ApiController]
[Route("api/devices")]
[Authorize] // admin JWT
public class DevicesController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly SystemSettingsProvider _settingsProvider;

    public DevicesController(AppDbContext db, SystemSettingsProvider settingsProvider)
    {
        _db = db;
        _settingsProvider = settingsProvider;
    }

    [HttpGet]
    public async Task<ActionResult<List<DeviceListItemDto>>> List()
    {
        var thresholds = await _settingsProvider.GetAlertThresholdsAsync();
        var onlineCutoff = DateTime.UtcNow.AddMinutes(-thresholds.StaleDeviceMinutes);

        var devices = await _db.Devices
            .Where(d => d.IsActive)
            .Select(d => new
            {
                d.Id,
                d.HardwareDeviceId,
                d.DeviceName,
                d.Username,
                d.Department,
                d.WindowsVersion,
                d.IpAddress,
                d.LastSeenUtc,
                d.CurrentRiskScore,
                UnresolvedAlertCount = d.Alerts.Count(a => !a.IsResolved)
            })
            .ToListAsync();

        var result = devices.Select(d => new DeviceListItemDto(
            d.Id, d.HardwareDeviceId, d.DeviceName, d.Username, d.Department, d.WindowsVersion, d.IpAddress,
            d.LastSeenUtc, d.LastSeenUtc >= onlineCutoff, d.CurrentRiskScore,
            RiskLevelHelper.Classify(d.CurrentRiskScore, thresholds.HighRiskThreshold), d.UnresolvedAlertCount
        )).OrderByDescending(d => d.CurrentRiskScore).ToList();

        return Ok(result);
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<DeviceDetailDto>> Detail(int id, [FromQuery] int historyPoints = 50)
    {
        var device = await _db.Devices.FirstOrDefaultAsync(d => d.Id == id);
        if (device is null) return NotFound();

        var thresholds = await _settingsProvider.GetAlertThresholdsAsync();
        bool isOnline = device.LastSeenUtc >= DateTime.UtcNow.AddMinutes(-thresholds.StaleDeviceMinutes);

        var latestSnapshot = await _db.SecurityStatusSnapshots
            .Where(s => s.DeviceId == id)
            .OrderByDescending(s => s.ReportedUtc)
            .FirstOrDefaultAsync();

        var history = await _db.SecurityStatusSnapshots
            .Where(s => s.DeviceId == id)
            .OrderByDescending(s => s.ReportedUtc)
            .Take(historyPoints)
            .Select(s => new RiskHistoryPointDto(s.ReportedUtc, s.RiskScore))
            .ToListAsync();

        var installedSoftware = await _db.InstalledSoftware
            .Where(s => s.DeviceId == id && s.CurrentlyInstalled)
            .OrderBy(s => s.SoftwareName)
            .Select(s => s.SoftwareName)
            .ToListAsync();

        var unauthorizedSoftware = await _db.InstalledSoftware
            .Where(s => s.DeviceId == id && s.CurrentlyInstalled && s.IsUnauthorized)
            .Select(s => s.SoftwareName)
            .ToListAsync();

        var recentDownloads = await _db.DownloadEvents
            .Where(d => d.DeviceId == id)
            .OrderByDescending(d => d.DetectedUtc)
            .Take(20)
            .Select(d => new DownloadedFileInfoDto
            {
                FileName = d.FileName,
                FullPath = d.FullPath,
                Sha256 = d.Sha256,
                IsDigitallySigned = d.IsDigitallySigned,
                Publisher = d.Publisher,
                FileType = d.FileType,
                DetectedUtc = d.DetectedUtc,
                SourceFolder = d.SourceFolder,
                IsSuspicious = d.IsSuspicious
            })
            .ToListAsync();

        var recentUsb = await _db.UsbEvents
            .Where(u => u.DeviceId == id)
            .OrderByDescending(u => u.EventUtc)
            .Take(20)
            .Select(u => new UsbEventDto
            {
                DeviceDescription = u.DeviceDescription,
                DriveLetter = u.DriveLetter,
                SerialNumber = u.SerialNumber,
                InsertedUtc = u.EventUtc,
                EventType = u.EventType
            })
            .ToListAsync();

        var browserExtensionRecords = await _db.BrowserExtensions
            .Where(x => x.DeviceId == id && x.CurrentlyInstalled)
            .OrderBy(x => x.Browser).ThenBy(x => x.Name)
            .ToListAsync();

        var browserExtensions = browserExtensionRecords.Select(x => new BrowserExtensionSummaryDto(
            x.Browser, x.Profile, x.ExtensionId, x.Name, x.Version, x.Publisher,
            JsonSerializer.Deserialize<List<string>>(x.PermissionsJson) ?? new List<string>(),
            x.IsEnabled, x.IsFromWebStore, x.IsDeveloperMode, x.IsBlacklisted, x.HasDangerousPermissions,
            x.InstalledUtc
        )).ToList();

        SecurityStatusSnapshotDto? snapshotDto = latestSnapshot is null ? null : new SecurityStatusSnapshotDto(
            latestSnapshot.ReportedUtc,
            latestSnapshot.FirewallDomainEnabled && latestSnapshot.FirewallPrivateEnabled && latestSnapshot.FirewallPublicEnabled,
            latestSnapshot.DefenderAntivirusEnabled,
            latestSnapshot.DefenderRealTimeProtectionEnabled,
            latestSnapshot.DefenderDefinitionsStatus,
            latestSnapshot.BitLockerEncrypted,
            latestSnapshot.WindowsUpdatePendingCount,
            latestSnapshot.WindowsIsSupportedVersion,
            latestSnapshot.WifiSsid,
            latestSnapshot.WifiIsTrusted,
            latestSnapshot.RiskScore,
            JsonSerializer.Deserialize<List<string>>(latestSnapshot.RiskFactorsJson) ?? new List<string>()
        );

        var dto = new DeviceDetailDto(
            device.Id, device.HardwareDeviceId, device.DeviceName, device.Username, device.Department, device.WindowsVersion,
            device.IpAddress, device.MacAddress, device.SerialNumber,
            device.FirstEnrolledUtc, device.LastSeenUtc, isOnline, device.CurrentRiskScore,
            RiskLevelHelper.Classify(device.CurrentRiskScore, thresholds.HighRiskThreshold),
            snapshotDto,
            history.OrderBy(h => h.ReportedUtc).ToList(),
            installedSoftware, unauthorizedSoftware, recentDownloads, recentUsb,
            browserExtensions
        );

        return Ok(dto);
    }

    /// <summary>Admin assigns/updates a device's department from the device detail page.</summary>
    /// <summary>Admin assigns/updates a device's department from the device detail page.</summary>
    [HttpPatch("{id:int}")]
    [Authorize(Roles = EndpointSecurityAPI.Auth.AppRoles.ManagementRoles)] // Viewer is read-only
    public async Task<IActionResult> Update(int id, [FromBody] UpdateDeviceDto request)
    {
        var device = await _db.Devices.FirstOrDefaultAsync(d => d.Id == id);
        if (device is null) return NotFound();

        device.Department = string.IsNullOrWhiteSpace(request.Department) ? null : request.Department.Trim();
        await _db.SaveChangesAsync();

        return NoContent();
    }
}
