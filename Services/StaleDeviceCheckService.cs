using EndpointSecurityAPI.Data;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Services;

/// <summary>
/// Periodically scans for devices that haven't reported in within the
/// configured window (Configuration page's Alert Thresholds → Stale Device
/// Minutes) and raises an Alert. This is the "device not reported in for a
/// defined period" item from the plan's Phase 5 list — implemented here
/// since it needs a recurring background job, which belongs in the API host.
/// </summary>
public class StaleDeviceCheckService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<StaleDeviceCheckService> _logger;

    public StaleDeviceCheckService(IServiceScopeFactory scopeFactory, IConfiguration config, ILogger<StaleDeviceCheckService> logger)
    {
        _scopeFactory = scopeFactory;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Sweep interval itself isn't exposed on the Configuration page (it's
        // "how often do we check", not a security threshold), so it's fine
        // to read this once from appsettings.json at startup.
        var sweepIntervalMinutes = _config.GetValue<int>("AlertSettings:StaleDeviceSweepIntervalMinutes", 10);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var alertService = scope.ServiceProvider.GetRequiredService<AlertService>();
                var settingsProvider = scope.ServiceProvider.GetRequiredService<SystemSettingsProvider>();

                // Re-read every sweep (not just once at startup) so an admin
                // editing "Stale Device Minutes" on the Configuration page
                // takes effect on the next sweep, not after a restart.
                var thresholds = await settingsProvider.GetAlertThresholdsAsync(stoppingToken);
                var cutoff = DateTime.UtcNow.AddMinutes(-thresholds.StaleDeviceMinutes);

                var staleDevices = await db.Devices
                    .Where(d => d.IsActive && d.LastSeenUtc < cutoff)
                    .ToListAsync(stoppingToken);

                foreach (var device in staleDevices)
                {
                    await alertService.CreateOfflineAlertIfNeededAsync(device, stoppingToken);
                }

                if (staleDevices.Count > 0)
                    _logger.LogInformation("Stale device sweep: {Count} device(s) flagged as offline", staleDevices.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during stale device sweep");
            }

            await Task.Delay(TimeSpan.FromMinutes(sweepIntervalMinutes), stoppingToken);
        }
    }
}
