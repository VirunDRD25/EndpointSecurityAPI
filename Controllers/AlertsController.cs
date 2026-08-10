using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Controllers;

[ApiController]
[Route("api/alerts")]
[Authorize] // admin JWT
public class AlertsController : ControllerBase
{
    private readonly AppDbContext _db;

    public AlertsController(AppDbContext db)
    {
        _db = db;
    }

    [HttpGet]
    public async Task<ActionResult<List<AlertDto>>> List([FromQuery] bool? resolved, [FromQuery] int take = 100)
    {
        var query = _db.Alerts.Include(a => a.Device).AsQueryable();

        if (resolved.HasValue)
            query = query.Where(a => a.IsResolved == resolved.Value);

        // Materialize first, then map to DTO in-memory — translating
        // enum.ToString() directly inside the EF query isn't reliably
        // supported by the MySQL provider.
        var alerts = await query
            .OrderByDescending(a => a.CreatedUtc)
            .Take(take)
            .ToListAsync();

        var result = alerts.Select(a => new AlertDto(
            a.Id, a.DeviceId, a.Device?.DeviceName ?? "Unknown", a.Type.ToString(), a.Severity.ToString(),
            a.Message, a.CreatedUtc, a.IsResolved, a.ResolvedUtc)).ToList();

        return Ok(result);
    }

    [HttpPost("{id:int}/resolve")]
    [Authorize(Roles = EndpointSecurityAPI.Auth.AppRoles.ManagementRoles)] // Viewer is read-only
    public async Task<IActionResult> Resolve(int id)
    {
        var alert = await _db.Alerts.FindAsync(id);
        if (alert is null) return NotFound();

        alert.IsResolved = true;
        alert.ResolvedUtc = DateTime.UtcNow;
        alert.ResolvedBy = User.Identity?.Name ?? "unknown";

        await _db.SaveChangesAsync();
        return NoContent();
    }
}
