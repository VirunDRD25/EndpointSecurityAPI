using System.Text.Json;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Services;

/// <summary>
/// Reads the singleton SystemSettings row so alert/dashboard logic reacts to
/// changes made on the Phase 4 Configuration page without a redeploy.
/// Queried per-call rather than cached in memory — this is one small row,
/// hit at most a few times per report cycle, so the simplicity of "always
/// read the current value" outweighs the cost of a cache invalidation path.
/// </summary>
public class SystemSettingsProvider
{
    private readonly AppDbContext _db;

    private static readonly AlertThresholdsDto DefaultAlertThresholds = new(50, 30);
    private static readonly RiskWeightsDto DefaultRiskWeights = new(20, 30, 15, 10, 15, 15, 25, 25, 10, 10, 20, 25, 10, 30, 20, 10);
    public SystemSettingsProvider(AppDbContext db)
    {
        _db = db;
    }

    public async Task<AlertThresholdsDto> GetAlertThresholdsAsync(CancellationToken ct = default)
    {
        var settings = await _db.SystemSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct);
        if (settings is null) return DefaultAlertThresholds;

        try
        {
            return JsonSerializer.Deserialize<AlertThresholdsDto>(settings.AlertThresholdsJson) ?? DefaultAlertThresholds;
        }
        catch
        {
            return DefaultAlertThresholds;
        }
    }

    public async Task<RiskWeightsDto> GetRiskWeightsAsync(CancellationToken ct = default)
    {
        var settings = await _db.SystemSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct);
        if (settings is null) return DefaultRiskWeights;

        try
        {
            return JsonSerializer.Deserialize<RiskWeightsDto>(settings.RiskWeightsJson) ?? DefaultRiskWeights;
        }
        catch
        {
            return DefaultRiskWeights;
        }
    }

    public async Task<List<string>> GetApprovedSoftwareAsync(CancellationToken ct = default)
    {
        var settings = await _db.SystemSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct);
        if (settings is null) return new List<string>();

        try
        {
            return JsonSerializer.Deserialize<List<string>>(settings.ApprovedSoftwareJson) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    public async Task<List<string>> GetTrustedWifiSsidsAsync(CancellationToken ct = default)
    {
        var settings = await _db.SystemSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct);
        if (settings is null) return new List<string>();

        try
        {
            return JsonSerializer.Deserialize<List<string>>(settings.TrustedWifiSsidsJson) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }
}
