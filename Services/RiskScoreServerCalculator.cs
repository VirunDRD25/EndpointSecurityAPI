using EndpointSecurityAPI.Dtos;

namespace EndpointSecurityAPI.Services;

/// <summary>
/// Server-side risk score calculator. Runs on every incoming agent report
/// using the weights stored in SystemSettings (the Configuration page),
/// completely overriding whatever score the agent calculated locally.
/// This ensures that changing weights in the dashboard immediately affects
/// future reports without needing to update every agent's appsettings.json.
/// </summary>
public static class RiskScoreServerCalculator
{
    public static (int score, List<string> factors) Calculate(DeviceReportDto report, RiskWeightsDto w)
    {
        int score = 0;
        var factors = new List<string>();

        // --- Firewall ---
        if (!report.Firewall.DomainEnabled || !report.Firewall.PrivateEnabled || !report.Firewall.PublicEnabled)
        {
            score += w.FirewallDisabled;
            factors.Add("Firewall disabled on one or more network profiles");
        }

        // --- Defender / AV ---
        if (!report.Defender.StatusReadSuccessfully)
        {
            factors.Add("Defender status could not be read (agent may need to run elevated/as a service)");
        }
        else
        {
            if (!report.Defender.AntivirusEnabled)
            {
                score += w.DefenderDisabled;
                factors.Add("Microsoft Defender antivirus is disabled");
            }
            else if (!report.Defender.RealTimeProtectionEnabled)
            {
                score += w.RealtimeProtectionDisabled;
                factors.Add("Real-time protection is disabled");
            }

            if (report.Defender.DefinitionsStatus == "Outdated")
            {
                score += w.DefinitionsOutdated;
                factors.Add($"Virus definitions are {report.Defender.DefinitionAgeDays} day(s) old");
            }
        }

        // --- BitLocker ---
        if (!report.BitLocker.SystemDriveEncrypted)
        {
            score += w.BitLockerOff;
            factors.Add("BitLocker is not enabled on the system drive");
        }

        // --- Windows Update ---
        if (report.WindowsUpdate.PendingUpdateCount > 0)
        {
            score += w.WindowsUpdatesPending;
            factors.Add($"{report.WindowsUpdate.PendingUpdateCount} Windows update(s) pending");
        }

        if (!report.WindowsUpdate.IsSupportedVersion)
        {
            score += w.UnsupportedWindowsVersion;
            factors.Add("Device is running an unsupported Windows version/build");
        }

        // --- Software ---
        if (report.UnauthorizedSoftware.Count > 0)
        {
            score += w.UnauthorizedSoftware;
            factors.Add($"Unauthorized software detected: {string.Join(", ", report.UnauthorizedSoftware)}");
        }

        // --- Downloads ---
        if (report.RecentDownloads.Any(d => d.IsSuspicious))
        {
            score += w.SuspiciousDownload;
            var names = string.Join(", ", report.RecentDownloads.Where(d => d.IsSuspicious).Select(d => d.FileName));
            factors.Add($"Unsigned/suspicious executable(s) downloaded: {names}");
        }

        // --- USB ---
        if (report.UsbEvents.Any(u => u.EventType == "Inserted"))
        {
            score += w.UnapprovedUsbConnected;
            factors.Add("USB storage device connected");
        }

        // --- Wi-Fi ---
        if (report.Wifi.ConnectedSsid != null && !report.Wifi.IsTrusted)
        {
            score += w.UntrustedWifi;
            factors.Add($"Connected to untrusted Wi-Fi network: {report.Wifi.ConnectedSsid}");
        }

        // --- Browser Extensions ---
        if (report.BrowserExtensions.Any(e => e.IsBlacklisted))
        {
            score += w.BlacklistedExtension;
            var names = string.Join(", ", report.BrowserExtensions
                .Where(e => e.IsBlacklisted).Select(e => e.Name).Distinct());
            factors.Add($"Blacklisted browser extension(s) detected: {names}");
        }

        if (report.BrowserExtensions.Any(e => e.IsDeveloperMode))
        {
            score += w.DeveloperModeExtension;
            var names = string.Join(", ", report.BrowserExtensions
                .Where(e => e.IsDeveloperMode).Select(e => e.Name).Distinct());
            factors.Add($"Developer-mode (unpacked) browser extension(s): {names}");
        }

        if (report.BrowserExtensions.Any(e => e.Publisher == "Unknown"))
        {
            score += w.UnknownPublisherExtension;
            factors.Add("Browser extension(s) from an unknown publisher detected");
        }

        if (report.BrowserExtensions.Any(e => e.HasDangerousPermissions))
        {
            score += w.DangerousExtensionPermissions;
            factors.Add("Browser extension(s) requesting dangerous permissions detected");
        }

        if (report.MissingRequiredSecurityExtensions.Count > 0)
        {
            score += w.SecurityExtensionRemoved;
            factors.Add($"Required security extension(s) missing: {string.Join(", ", report.MissingRequiredSecurityExtensions)}");
        }

        return (Math.Min(score, 100), factors);
    }
}