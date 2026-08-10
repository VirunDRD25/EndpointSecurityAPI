using System.Text.Json;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using EndpointSecurityAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Controllers;

[ApiController]
[Route("api/settings")]
[Authorize(Roles = EndpointSecurityAPI.Auth.AppRoles.ManagementRoles)] // Admin + Cybersecurity Team only — Viewer cannot access Configuration
public class SettingsController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly SoftwareReauthorizationService _reauthService;
    private readonly RiskScoreRecomputeService _recomputeService;

    private static readonly RiskWeightsDto DefaultRiskWeights =
        new(20, 30, 15, 10, 15, 15, 25, 25, 10, 10, 20, 25, 10, 30, 20, 10);
    private static readonly AlertThresholdsDto DefaultAlertThresholds = new(50, 30);

    public SettingsController(
        AppDbContext db,
        SoftwareReauthorizationService reauthService,
        RiskScoreRecomputeService recomputeService)
    {
        _db = db;
        _reauthService = reauthService;
        _recomputeService = recomputeService;
    }

    [HttpGet]
    public async Task<ActionResult<SystemSettingsDto>> Get()
    {
        var settings = await GetOrCreateAsync();
        return Ok(ToDto(settings));
    }

    [HttpPut]
    public async Task<ActionResult<SystemSettingsDto>> Update([FromBody] UpdateSystemSettingsDto request)
    {
        var settings = await GetOrCreateAsync();

        var newApprovedSoftware = request.ApprovedSoftware ?? new List<string>();

        settings.ApprovedSoftwareJson = JsonSerializer.Serialize(newApprovedSoftware);
        settings.TrustedWifiSsidsJson = JsonSerializer.Serialize(request.TrustedWifiSsids ?? new List<string>());
        settings.BlacklistedExtensionsJson = JsonSerializer.Serialize(request.BlacklistedExtensions ?? new List<string>());
        settings.RequiredSecurityExtensionsJson = JsonSerializer.Serialize(request.RequiredSecurityExtensions ?? new List<string>());
        settings.RiskWeightsJson = JsonSerializer.Serialize(request.RiskWeights ?? DefaultRiskWeights);
        settings.AlertThresholdsJson = JsonSerializer.Serialize(request.AlertThresholds ?? DefaultAlertThresholds);
        settings.UpdatedUtc = DateTime.UtcNow;
        settings.UpdatedBy = User.Identity?.Name ?? "unknown";

        await _db.SaveChangesAsync();

        // Immediately re-check every device's software authorization status.
        await _reauthService.ReevaluateAllDevicesAsync(newApprovedSoftware);

        // Immediately recompute every device's risk score using the new weights
        // so the dashboard reflects the change without waiting for the next
        // agent report cycle.
        await _recomputeService.RecomputeAllAsync(request.RiskWeights ?? DefaultRiskWeights);

        return Ok(ToDto(settings));
    }

    private async Task<Entities.SystemSettings> GetOrCreateAsync()
    {
        var settings = await _db.SystemSettings.FirstOrDefaultAsync(s => s.Id == 1);
        if (settings != null) return settings;

        // Defensive fallback in case the seeded row (Id=1) was somehow removed.
        settings = new Entities.SystemSettings
        {
            Id = 1,
            ApprovedSoftwareJson = "[]",
            TrustedWifiSsidsJson = "[]",
            BlacklistedExtensionsJson = "[]",
            RequiredSecurityExtensionsJson = "[]",
            RiskWeightsJson = JsonSerializer.Serialize(DefaultRiskWeights),
            AlertThresholdsJson = JsonSerializer.Serialize(DefaultAlertThresholds),
            UpdatedUtc = DateTime.UtcNow
        };
        _db.SystemSettings.Add(settings);
        await _db.SaveChangesAsync();
        return settings;
    }

    private static SystemSettingsDto ToDto(Entities.SystemSettings s) => new(
        JsonSerializer.Deserialize<List<string>>(s.ApprovedSoftwareJson) ?? new(),
        JsonSerializer.Deserialize<List<string>>(s.TrustedWifiSsidsJson) ?? new(),
        JsonSerializer.Deserialize<List<string>>(s.BlacklistedExtensionsJson) ?? new(),
        JsonSerializer.Deserialize<List<string>>(s.RequiredSecurityExtensionsJson) ?? new(),
        JsonSerializer.Deserialize<RiskWeightsDto>(s.RiskWeightsJson) ?? DefaultRiskWeights,
        JsonSerializer.Deserialize<AlertThresholdsDto>(s.AlertThresholdsJson) ?? DefaultAlertThresholds,
        s.UpdatedUtc,
        s.UpdatedBy
    );
}