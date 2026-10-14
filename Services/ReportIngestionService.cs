using System.Text.Json;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using EndpointSecurityAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Services;

public class ReportIngestionService
{
    private readonly AppDbContext _db;
    private readonly AlertService _alertService;
    private readonly SystemSettingsProvider _settingsProvider;
    private readonly ILogger<ReportIngestionService> _logger;

    public ReportIngestionService(
        AppDbContext db,
        AlertService alertService,
        SystemSettingsProvider settingsProvider,
        ILogger<ReportIngestionService> logger)
    {
        _db = db;
        _alertService = alertService;
        _settingsProvider = settingsProvider;
        _logger = logger;
    }

    public async Task<Device> IngestAsync(DeviceReportDto report, int enrollmentTokenId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(report.DeviceId))
            throw new ArgumentException("Report is missing deviceId (hardware UUID) — cannot identify device.");

        var device = await _db.Devices
            .FirstOrDefaultAsync(d => d.HardwareDeviceId == report.DeviceId, ct);

        if (device is null)
        {
            device = new Device
            {
                HardwareDeviceId = report.DeviceId,
                FirstEnrolledUtc = DateTime.UtcNow,
                EnrolledViaTokenId = enrollmentTokenId
            };
            _db.Devices.Add(device);
            _logger.LogInformation("New device auto-enrolled: {DeviceId} ({Name})", report.DeviceId, report.DeviceName);
        }

        // ---------------------------------------------------------------
        // Server is the single source of truth for unauthorized software
        // AND risk score — both are recomputed using live DB settings so
        // that Configuration page changes take effect without touching the
        // agent's local appsettings.json / ApprovedSoftware.json.
        // ---------------------------------------------------------------
        var approvedSoftware = await _settingsProvider.GetApprovedSoftwareAsync(ct);
        report.UnauthorizedSoftware = SoftwareAuthorizationHelper
            .DetermineUnauthorized(report.InstalledSoftware, approvedSoftware);

        var riskWeights = await _settingsProvider.GetRiskWeightsAsync(ct);
        var (serverScore, serverFactors) = RiskScoreServerCalculator.Calculate(report, riskWeights);
        report.RiskScore = serverScore;
        report.RiskFactors = serverFactors;

        // Refresh identity/hardware fields every report.
        device.DeviceName = report.DeviceName;
        device.Username = report.Username;
        device.WindowsVersion = report.WindowsVersion;
        device.IpAddress = report.IpAddress;
        device.MacAddress = report.MacAddress;
        device.SerialNumber = report.SerialNumber;
        device.LastSeenUtc = DateTime.UtcNow;
        device.CurrentRiskScore = report.RiskScore;   // now the server-computed value
        device.IsActive = true;

        var snapshot = new SecurityStatusSnapshot
        {
            Device = device,
            ReportedUtc = DateTime.UtcNow,

            FirewallDomainEnabled = report.Firewall.DomainEnabled,
            FirewallPrivateEnabled = report.Firewall.PrivateEnabled,
            FirewallPublicEnabled = report.Firewall.PublicEnabled,

            DefenderAntivirusEnabled = report.Defender.AntivirusEnabled,
            DefenderRealTimeProtectionEnabled = report.Defender.RealTimeProtectionEnabled,
            DefenderDefinitionsStatus = report.Defender.DefinitionsStatus,
            DefenderDefinitionAgeDays = report.Defender.DefinitionAgeDays,
            DefenderStatusReadSuccessfully = report.Defender.StatusReadSuccessfully,

            BitLockerEncrypted = report.BitLocker.SystemDriveEncrypted,
            BitLockerProtectionStatus = report.BitLocker.ProtectionStatus,
            BitLockerEncryptionPercentage = report.BitLocker.EncryptionPercentage,

            WindowsUpdateLastInstalledUtc = report.WindowsUpdate.LastInstalledUtc,
            WindowsUpdatePendingCount = report.WindowsUpdate.PendingUpdateCount,
            WindowsIsSupportedVersion = report.WindowsUpdate.IsSupportedVersion,

            WifiSsid = report.Wifi.ConnectedSsid,
            WifiIsTrusted = report.Wifi.IsTrusted,
            WifiSignalStrengthPercent = report.Wifi.SignalStrengthPercent,

            RiskScore = report.RiskScore,
            RiskFactorsJson = JsonSerializer.Serialize(report.RiskFactors),
            UnauthorizedSoftwareJson = JsonSerializer.Serialize(report.UnauthorizedSoftware)
        };

        _db.SecurityStatusSnapshots.Add(snapshot);

        await UpsertSoftwareInventoryAsync(device, report, ct);
        await AddDownloadEventsAsync(device, report, ct);
        await AddUsbEventsAsync(device, report, ct);
        var newExtensions = await UpsertBrowserExtensionsAsync(device, report, ct);
        var newHighRiskFiles = await AddFileRisksAsync(device, report, ct);

        await _db.SaveChangesAsync(ct);

        // Generate alerts AFTER save so DeviceId is populated.
        var newExtensionNames = newExtensions.Select(x => x.Name).Distinct().ToList();
        await _alertService.EvaluateAndCreateAlertsAsync(device, report, ct, newExtensionNames, newHighRiskFiles);

        return device;
    }

    private async Task UpsertSoftwareInventoryAsync(Device device, DeviceReportDto report, CancellationToken ct)
    {
        var existing = await _db.InstalledSoftware
            .Where(s => s.DeviceId == device.Id)
            .ToListAsync(ct);

        var existingByName = existing.ToDictionary(s => s.SoftwareName, StringComparer.OrdinalIgnoreCase);
        var reportedSet = new HashSet<string>(report.InstalledSoftware, StringComparer.OrdinalIgnoreCase);
        var unauthorizedSet = new HashSet<string>(report.UnauthorizedSoftware, StringComparer.OrdinalIgnoreCase);

        foreach (var name in report.InstalledSoftware)
        {
            if (existingByName.TryGetValue(name, out var record))
            {
                record.LastSeenUtc = DateTime.UtcNow;
                record.CurrentlyInstalled = true;
                record.IsUnauthorized = unauthorizedSet.Contains(name);
            }
            else
            {
                _db.InstalledSoftware.Add(new InstalledSoftwareRecord
                {
                    Device = device,
                    SoftwareName = name,
                    FirstSeenUtc = DateTime.UtcNow,
                    LastSeenUtc = DateTime.UtcNow,
                    CurrentlyInstalled = true,
                    IsUnauthorized = unauthorizedSet.Contains(name)
                });
            }
        }

        foreach (var record in existing)
        {
            if (!reportedSet.Contains(record.SoftwareName))
                record.CurrentlyInstalled = false;
        }
    }

    private async Task AddDownloadEventsAsync(Device device, DeviceReportDto report, CancellationToken ct)
    {
        foreach (var file in report.RecentDownloads)
        {
            bool alreadyLogged = await _db.DownloadEvents.AnyAsync(d =>
                d.DeviceId == device.Id && d.Sha256 == file.Sha256 && d.FullPath == file.FullPath, ct);

            if (alreadyLogged) continue;

            _db.DownloadEvents.Add(new DownloadEvent
            {
                Device = device,
                FileName = file.FileName,
                FullPath = file.FullPath,
                Sha256 = file.Sha256,
                IsDigitallySigned = file.IsDigitallySigned,
                Publisher = file.Publisher,
                FileType = file.FileType,
                SourceFolder = file.SourceFolder,
                IsSuspicious = file.IsSuspicious,
                DetectedUtc = file.DetectedUtc == default ? DateTime.UtcNow : file.DetectedUtc
            });
        }
    }

    private async Task AddUsbEventsAsync(Device device, DeviceReportDto report, CancellationToken ct)
    {
        foreach (var usb in report.UsbEvents)
        {
            _db.UsbEvents.Add(new UsbEventRecord
            {
                Device = device,
                DeviceDescription = usb.DeviceDescription,
                DriveLetter = usb.DriveLetter,
                SerialNumber = usb.SerialNumber,
                EventType = usb.EventType,
                EventUtc = usb.InsertedUtc == default ? DateTime.UtcNow : usb.InsertedUtc
            });
        }
        await Task.CompletedTask;
    }

    private async Task<List<BrowserExtensionRecord>> UpsertBrowserExtensionsAsync(Device device, DeviceReportDto report, CancellationToken ct)
    {
        var existing = await _db.BrowserExtensions
            .Where(x => x.DeviceId == device.Id)
            .ToListAsync(ct);

        var existingByKey = existing.ToDictionary(x => (x.Browser, x.Profile, x.ExtensionId));
        var reportedKeys = new HashSet<(string, string, string)>();
        var newlySeen = new List<BrowserExtensionRecord>();

        foreach (var ext in report.BrowserExtensions)
        {
            var key = (ext.Browser, ext.Profile, ext.ExtensionId);
            reportedKeys.Add(key);

            if (existingByKey.TryGetValue(key, out var record))
            {
                record.Name = ext.Name;
                record.Version = ext.Version;
                record.Publisher = ext.Publisher;
                record.PermissionsJson = JsonSerializer.Serialize(ext.Permissions);
                record.IsEnabled = ext.IsEnabled;
                record.IsFromWebStore = ext.IsFromWebStore;
                record.IsDeveloperMode = ext.IsDeveloperMode;
                record.IsBlacklisted = ext.IsBlacklisted;
                record.HasDangerousPermissions = ext.HasDangerousPermissions;
                record.InstalledUtc = ext.InstalledUtc;
                record.LastSeenUtc = DateTime.UtcNow;
                record.CurrentlyInstalled = true;
            }
            else
            {
                var newRecord = new BrowserExtensionRecord
                {
                    Device = device,
                    Browser = ext.Browser,
                    Profile = ext.Profile,
                    ExtensionId = ext.ExtensionId,
                    Name = ext.Name,
                    Version = ext.Version,
                    Publisher = ext.Publisher,
                    PermissionsJson = JsonSerializer.Serialize(ext.Permissions),
                    IsEnabled = ext.IsEnabled,
                    IsFromWebStore = ext.IsFromWebStore,
                    IsDeveloperMode = ext.IsDeveloperMode,
                    IsBlacklisted = ext.IsBlacklisted,
                    HasDangerousPermissions = ext.HasDangerousPermissions,
                    InstalledUtc = ext.InstalledUtc,
                    FirstSeenUtc = DateTime.UtcNow,
                    LastSeenUtc = DateTime.UtcNow,
                    CurrentlyInstalled = true
                };
                _db.BrowserExtensions.Add(newRecord);
                newlySeen.Add(newRecord);
            }
        }

        foreach (var record in existing)
        {
            var key = (record.Browser, record.Profile, record.ExtensionId);
            if (!reportedKeys.Contains(key))
                record.CurrentlyInstalled = false;
        }

        return newlySeen;
    }

        /// <summary>
    /// Metadata-only File Risk Analyzer ingestion: persists new/changed
    /// FileRiskRecord rows reported by the agent (name, path, extension,
    /// size, SHA-256, timestamps, computed risk level/reasons — never file
    /// contents). Batches the existing-record lookup into a single query
    /// (same pattern as UpsertSoftwareInventoryAsync/UpsertBrowserExtensionsAsync
    /// above) instead of one query per file, since a device can report
    /// hundreds of files per cycle. Returns the High-risk subset so
    /// AlertService can raise a single bundled alert.
    /// </summary>
    private async Task<List<FileRiskRecord>> AddFileRisksAsync(Device device, DeviceReportDto report, CancellationToken ct)
    {
        var newHighRiskFiles = new List<FileRiskRecord>();

        var existing = await _db.FileRiskRecords
            .Where(r => r.DeviceId == device.Id)
            .Select(r => new { r.FilePath, r.FileModifiedUtc })
            .ToListAsync(ct);

        var lastModifiedByPath = existing
            .GroupBy(r => r.FilePath)
            .ToDictionary(g => g.Key, g => g.Max(r => r.FileModifiedUtc));

        foreach (var f in report.FileRisks)
        {
            if (lastModifiedByPath.TryGetValue(f.FilePath, out var lastModified) && lastModified >= f.ModifiedUtc)
                continue;

            var record = new FileRiskRecord
            {
                Device = device,
                FileName = f.FileName,
                FilePath = f.FilePath,
                Extension = f.Extension,
                Category = f.Category,
                SizeBytes = f.SizeBytes,
                Sha256 = f.Sha256,
                FileCreatedUtc = f.CreatedUtc,
                FileModifiedUtc = f.ModifiedUtc,
                Location = f.Location,
                RiskLevel = f.RiskLevel,
                RiskReasons = f.RiskReasons.ToArray(),
                DetectedAt = DateTime.UtcNow
            };

            _db.FileRiskRecords.Add(record);

            if (record.RiskLevel == "High")
                newHighRiskFiles.Add(record);
        }

        return newHighRiskFiles;
    }
}