namespace EndpointSecurityAPI.Entities;

/// <summary>
/// A shared secret baked into appsettings.json before rolling the agent out
/// (e.g. via GPO/SCCM to hundreds of laptops). It authenticates ANY device
/// carrying it — devices are individually identified afterwards by their
/// hardware UUID in the report payload, not by having a unique token each.
/// This trades "unique token per device" for "practical to mass-deploy";
/// revoke + reissue a token if it leaks, and issue separate tokens per
/// department/office if you want blast-radius isolation.
/// </summary>
public class EnrollmentToken
{
    public int Id { get; set; }

    public string Label { get; set; } = string.Empty;

    /// <summary>BCrypt hash of the raw token. The raw value is shown to the admin ONCE at creation time.</summary>
    public string TokenHash { get; set; } = string.Empty;

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? RevokedUtc { get; set; }
    public bool IsActive { get; set; } = true;

    public ICollection<Device> EnrolledDevices { get; set; } = new List<Device>();
}
