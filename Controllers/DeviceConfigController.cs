using EndpointSecurityAPI.Auth;
using EndpointSecurityAPI.Dtos;
using EndpointSecurityAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EndpointSecurityAPI.Controllers;

/// <summary>
/// Lets an agent pull the centrally-managed approved software list, trusted
/// Wi-Fi list, and risk weights instead of relying on its own local
/// appsettings.json / ApprovedSoftware.json.
///
/// NOT YET CALLED BY THE PHASE 1 AGENT — this endpoint exists so the data is
/// available, but Worker.cs still reads its local files. Wiring the agent to
/// call this on startup (and periodically) is a follow-up Phase 1 change;
/// until then, edits made on the dashboard's Configuration page only affect
/// server-side alerting (via SystemSettingsProvider), not what the agent
/// itself flags as unauthorized software.
/// </summary>
[ApiController]
[Route("api/device")]
[Authorize(AuthenticationSchemes = DeviceTokenDefaults.AuthenticationScheme)]
public class DeviceConfigController : ControllerBase
{
    private readonly SystemSettingsProvider _settingsProvider;

    public DeviceConfigController(SystemSettingsProvider settingsProvider)
    {
        _settingsProvider = settingsProvider;
    }

    [HttpGet("config")]
    public async Task<ActionResult<DeviceConfigDto>> GetConfig(CancellationToken ct)
    {
        var approvedSoftware = await _settingsProvider.GetApprovedSoftwareAsync(ct);
        var trustedWifi = await _settingsProvider.GetTrustedWifiSsidsAsync(ct);
        var riskWeights = await _settingsProvider.GetRiskWeightsAsync(ct);

        return Ok(new DeviceConfigDto(approvedSoftware, trustedWifi, riskWeights));
    }
}
