namespace EndpointSecurityAPI.Dtos;

public record AdminUserDto(
    int Id,
    string Username,
    string Role,
    DateTime CreatedUtc,
    DateTime? LastLoginUtc,
    bool IsActive
);

public record CreateAdminUserDto(string Username, string Password, string Role);

/// <summary>Role and active status are both editable; username/password are not (password reset is a separate, deliberate action).</summary>
public record UpdateAdminUserDto(string Role, bool IsActive);
