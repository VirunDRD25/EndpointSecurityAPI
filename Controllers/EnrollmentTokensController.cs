using System.Security.Cryptography;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using EndpointSecurityAPI.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Controllers;

/// <summary>
/// Admin-only management of enrollment tokens — the shared secrets baked
/// into the agent's appsettings.json before mass rollout. See
/// Entities/EnrollmentToken.cs for the reasoning behind this model.
/// </summary>
[ApiController]
[Route("api/enrollment-tokens")]
[Authorize] // default scheme = JWT (admin dashboard), configured in Program.cs
public class EnrollmentTokensController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly ILogger<EnrollmentTokensController> _logger;

    public EnrollmentTokensController(AppDbContext db, ILogger<EnrollmentTokensController> logger)
    {
        _db = db;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<List<EnrollmentTokenSummaryDto>>> List()
    {
        var tokens = await _db.EnrollmentTokens
            .Select(t => new EnrollmentTokenSummaryDto(
                t.Id, t.Label, t.CreatedUtc, t.IsActive,
                t.EnrolledDevices.Count))
            .ToListAsync();

        return Ok(tokens);
    }

    [HttpPost]
    public async Task<ActionResult<CreateEnrollmentTokenResponseDto>> Create([FromBody] CreateEnrollmentTokenRequestDto request)
    {
        if (string.IsNullOrWhiteSpace(request.Label))
            return BadRequest(new { message = "Label is required (e.g. 'Colombo Office', 'Default')." });

        var rawToken = GenerateSecureToken();

        var entity = new EnrollmentToken
        {
            Label = request.Label.Trim(),
            TokenHash = BCrypt.Net.BCrypt.HashPassword(rawToken),
            CreatedUtc = DateTime.UtcNow,
            IsActive = true
        };

        _db.EnrollmentTokens.Add(entity);
        await _db.SaveChangesAsync();

        _logger.LogInformation("Enrollment token created: '{Label}' (id {Id}) by {User}", entity.Label, entity.Id, User.Identity?.Name);

        // Raw token is returned ONCE here — paste it into the agent's
        // appsettings.json AgentSettings:ApiKeyOrDeviceToken. It cannot be
        // retrieved again after this response.
        return Ok(new CreateEnrollmentTokenResponseDto(entity.Id, entity.Label, rawToken, entity.CreatedUtc));
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Revoke(int id)
    {
        var token = await _db.EnrollmentTokens.FindAsync(id);
        if (token is null) return NotFound();

        token.IsActive = false;
        token.RevokedUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        _logger.LogInformation("Enrollment token revoked: '{Label}' (id {Id}) by {User}", token.Label, token.Id, User.Identity?.Name);
        return NoContent();
    }

    private static string GenerateSecureToken()
    {
        // 32 random bytes -> URL-safe base64 -> a long opaque bearer token.
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }
}
