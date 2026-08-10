using EndpointSecurityAPI.Auth;
using EndpointSecurityAPI.Dtos;
using EndpointSecurityAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EndpointSecurityAPI.Controllers;

/// <summary>
/// This is the endpoint the Phase 1 Windows Agent posts to every report
/// cycle. Authenticated with the DeviceToken scheme (enrollment token),
/// NOT the admin JWT scheme — see Auth/DeviceTokenAuthenticationHandler.cs.
/// </summary>
[ApiController]
[Route("api/device")]
[Authorize(AuthenticationSchemes = DeviceTokenDefaults.AuthenticationScheme)]
public class DeviceReportController : ControllerBase
{
    private readonly ReportIngestionService _ingestionService;
    private readonly ILogger<DeviceReportController> _logger;

    public DeviceReportController(ReportIngestionService ingestionService, ILogger<DeviceReportController> logger)
    {
        _ingestionService = ingestionService;
        _logger = logger;
    }

    [HttpPost("report")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> Report([FromBody] DeviceReportDto report, CancellationToken ct)
    {
        if (report is null)
            return BadRequest(new { message = "Empty report body" });

        var enrollmentTokenIdClaim = User.FindFirst("EnrollmentTokenId")?.Value;
        if (!int.TryParse(enrollmentTokenIdClaim, out var enrollmentTokenId))
            return Unauthorized(new { message = "Could not resolve enrollment token from credentials" });

        try
        {
            var device = await _ingestionService.IngestAsync(report, enrollmentTokenId, ct);

            _logger.LogInformation("Report ingested for device {DeviceName} ({HardwareId}) — risk score {Score}",
                device.DeviceName, device.HardwareDeviceId, device.CurrentRiskScore);

            return Ok(new { status = "accepted", deviceId = device.Id, riskScore = device.CurrentRiskScore });
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning(ex, "Rejected malformed report");
            return BadRequest(new { message = ex.Message });
        }
    }
}
