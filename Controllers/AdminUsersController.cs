using System.Security.Claims;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using EndpointSecurityAPI.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Controllers;

/// <summary>
/// Admin account management — the "User permissions" item on the
/// Configuration page. Kept intentionally simple (Role is a free-standing
/// string like "Admin"/"Viewer" rather than a full RBAC system) since the
/// plan only calls for basic role assignment at this stage.
/// </summary>
[ApiController]
[Route("api/admin-users")]
[Authorize(Roles = EndpointSecurityAPI.Auth.AppRoles.ManagementRoles)] // Admin + Cybersecurity Team only — Viewer cannot see or manage users
public class AdminUsersController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly ILogger<AdminUsersController> _logger;

    public AdminUsersController(AppDbContext db, ILogger<AdminUsersController> logger)
    {
        _db = db;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<List<AdminUserDto>>> List()
    {
        var users = await _db.AdminUsers
            .OrderBy(u => u.Username)
            .Select(u => new AdminUserDto(u.Id, u.Username, u.Role, u.CreatedUtc, u.LastLoginUtc, u.IsActive))
            .ToListAsync();

        return Ok(users);
    }

    [HttpPost]
    public async Task<ActionResult<AdminUserDto>> Create([FromBody] CreateAdminUserDto request)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { message = "Username and password are required." });

        if (request.Password.Length < 8)
            return BadRequest(new { message = "Password must be at least 8 characters." });

        bool exists = await _db.AdminUsers.AnyAsync(u => u.Username == request.Username);
        if (exists) return Conflict(new { message = "That username is already taken." });

        var user = new AdminUser
        {
            Username = request.Username.Trim(),
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            Role = string.IsNullOrWhiteSpace(request.Role) ? "Viewer" : request.Role.Trim(),
            CreatedUtc = DateTime.UtcNow,
            IsActive = true
        };

        _db.AdminUsers.Add(user);
        await _db.SaveChangesAsync();

        _logger.LogInformation("Admin user '{Username}' created with role '{Role}' by {Actor}", user.Username, user.Role, User.Identity?.Name);

        return Ok(new AdminUserDto(user.Id, user.Username, user.Role, user.CreatedUtc, user.LastLoginUtc, user.IsActive));
    }

    [HttpPatch("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateAdminUserDto request)
    {
        var user = await _db.AdminUsers.FindAsync(id);
        if (user is null) return NotFound();

        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (currentUserId == id.ToString() && !request.IsActive)
            return BadRequest(new { message = "You can't deactivate your own account." });

        user.Role = string.IsNullOrWhiteSpace(request.Role) ? user.Role : request.Role.Trim();
        user.IsActive = request.IsActive;

        await _db.SaveChangesAsync();
        _logger.LogInformation("Admin user '{Username}' updated (role={Role}, active={Active}) by {Actor}",
            user.Username, user.Role, user.IsActive, User.Identity?.Name);

        return NoContent();
    }
}
