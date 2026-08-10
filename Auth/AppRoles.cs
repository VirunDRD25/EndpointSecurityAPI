namespace EndpointSecurityAPI.Auth;

public static class AppRoles
{
    public const string Admin = "Admin";
    public const string CybersecurityTeam = "Cybersecurity Team";
    public const string Viewer = "Viewer";

    /// <summary>
    /// Roles allowed to manage Configuration and User Permissions, and to
    /// perform any write action (resolve alerts, assign departments, create
    /// users). Viewer is intentionally excluded — read-only by design.
    /// </summary>
    public const string ManagementRoles = Admin + "," + CybersecurityTeam;
}