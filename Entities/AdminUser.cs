namespace EndpointSecurityAPI.Entities;

public class AdminUser
{
    public int Id { get; set; }

    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>"Admin" or "Viewer" — extend as needed.</summary>
    public string Role { get; set; } = "Admin";

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginUtc { get; set; }
    public bool IsActive { get; set; } = true;

    /// <summary>Where high-risk alert emails are sent. Null/empty = this admin receives no email notifications yet.</summary>
    public string? Email { get; set; }

    /// <summary>Self-service opt-out for high-risk alert emails — set via PATCH /api/admin-users/me/notifications.</summary>
    public bool NotificationsMuted { get; set; }
}