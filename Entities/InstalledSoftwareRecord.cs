namespace EndpointSecurityAPI.Entities;

/// <summary>
/// Current installed-software inventory per device. Upserted on every
/// report (FirstSeenUtc/LastSeenUtc track when something appeared and
/// whether it's still present), rather than storing the full list on every
/// snapshot row, which would balloon table size fast across hundreds of
/// devices reporting every 5 minutes.
/// </summary>
public class InstalledSoftwareRecord
{
    public int Id { get; set; }

    public int DeviceId { get; set; }
    public Device? Device { get; set; }

    public string SoftwareName { get; set; } = string.Empty;

    public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;

    /// <summary>False once a report comes in without this software present (uninstalled).</summary>
    public bool CurrentlyInstalled { get; set; } = true;

    public bool IsUnauthorized { get; set; }
}
