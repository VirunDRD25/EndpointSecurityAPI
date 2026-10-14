using System.Net.Mail;
using System.Security.Claims;
using EndpointSecurityAPI.Auth;
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
///
/// Class-level [Authorize] (no Roles) so any logged-in admin can hit the
/// /me endpoints below to manage their own email/notification settings.
/// The management actions (list/create/edit-others) add their own
/// Roles-restricted [Authorize] on top.
/// </summary>
[ApiController]
[Route("api/admin-users")]
[Authorize]
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
    [Authorize(Roles = AppRoles.ManagementRoles)]
    public async Task<ActionResult<List<AdminUserDto>>> List()
    {
        var users = await _db.AdminUsers
            .OrderBy(u => u.Username)
            .Select(u => new AdminUserDto(u.Id, u.Username, u.Email, u.Role, u.CreatedUtc, u.LastLoginUtc, u.IsActive, u.NotificationsMuted))
            .ToListAsync();

        return Ok(users);
    }

    [HttpPost]
    [Authorize(Roles = AppRoles.ManagementRoles)]
    public async Task<ActionResult<AdminUserDto>> Create([FromBody] CreateAdminUserDto request)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { message = "Username and password are required." });

        if (request.Password.Length < 8)
            return BadRequest(new { message = "Password must be at least 8 characters." });

        bool exists = await _db.AdminUsers.AnyAsync(u => u.Username == request.Username);
        if (exists) return Conflict(new { message = "That username is already taken." });

        string? email = null;
        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            try { _ = new MailAddress(request.Email.Trim()); }
            catch { return BadRequest(new { message = "That doesn't look like a valid email address." }); }
            email = request.Email.Trim();
        }

        var user = new AdminUser
        {
            Username = request.Username.Trim(),
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            Role = string.IsNullOrWhiteSpace(request.Role) ? "Viewer" : request.Role.Trim(),
            Email = email,
            CreatedUtc = DateTime.UtcNow,
            IsActive = true
        };

        _db.AdminUsers.Add(user);
        await _db.SaveChangesAsync();

        _logger.LogInformation("Admin user '{Username}' created with role '{Role}' by {Actor}", user.Username, user.Role, User.Identity?.Name);

        return Ok(new AdminUserDto(user.Id, user.Username, user.Email, user.Role, user.CreatedUtc, user.LastLoginUtc, user.IsActive, user.NotificationsMuted));
    }

    [HttpPatch("{id:int}")]
    [Authorize(Roles = AppRoles.ManagementRoles)]
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

    /// <summary>The logged-in admin's own account — used by the dashboard's "My Notification Settings" panel.</summary>
    [HttpGet("me")]
    public async Task<ActionResult<AdminUserDto>> GetMe()
    {
        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (currentUserId is null || !int.TryParse(currentUserId, out var id)) return Unauthorized();

        var user = await _db.AdminUsers.FindAsync(id);
        if (user is null) return NotFound();

        return Ok(new AdminUserDto(user.Id, user.Username, user.Email, user.Role, user.CreatedUtc, user.LastLoginUtc, user.IsActive, user.NotificationsMuted));
    }

    /// <summary>Self-service: set/clear your notification email and mute/unmute high-risk alert emails.</summary>
    [HttpPatch("me/notifications")]
    public async Task<ActionResult<AdminUserDto>> UpdateMyNotificationPreferences([FromBody] UpdateNotificationPreferencesDto request)
    {
        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (currentUserId is null || !int.TryParse(currentUserId, out var id)) return Unauthorized();

        var user = await _db.AdminUsers.FindAsync(id);
        if (user is null) return NotFound();

        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            try { _ = new MailAddress(request.Email.Trim()); }
            catch { return BadRequest(new { message = "That doesn't look like a valid email address." }); }
            user.Email = request.Email.Trim();
        }
        else if (request.Email is not null)
        {
            // Explicitly sent as "" — treat as "clear the email".
            user.Email = null;
        }

        user.NotificationsMuted = request.NotificationsMuted;

        await _db.SaveChangesAsync();
        _logger.LogInformation("Admin user '{Username}' updated their own notification preferences (muted={Muted})",
            user.Username, user.NotificationsMuted);

        return Ok(new AdminUserDto(user.Id, user.Username, user.Email, user.Role, user.CreatedUtc, user.LastLoginUtc, user.IsActive, user.NotificationsMuted));
    }
}