namespace EndpointSecurityAPI.Dtos;

public record AdminUserDto(
    int Id,
    string Username,
    string? Email,
    string Role,
    DateTime CreatedUtc,
    DateTime? LastLoginUtc,
    bool IsActive,
    bool NotificationsMuted
);

public record CreateAdminUserDto(string Username, string Password, string Role, string? Email);

/// <summary>Role and active status are both editable; username/password are not (password reset is a separate, deliberate action). Email is edited by the user themselves via /me/notifications, not here.</summary>
public record UpdateAdminUserDto(string Role, bool IsActive);

/// <summary>Self-service: an admin editing their own email and mute state. Email == null means "leave unchanged"; Email == "" means "clear it".</summary>
public record UpdateNotificationPreferencesDto(string? Email, bool NotificationsMuted);