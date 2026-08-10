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
}
