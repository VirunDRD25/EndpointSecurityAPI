namespace EndpointSecurityAPI.Entities;

public class UsbEventRecord
{
    public int Id { get; set; }

    public int DeviceId { get; set; }
    public Device? Device { get; set; }

    public string DeviceDescription { get; set; } = string.Empty;
    public string? DriveLetter { get; set; }
    public string? SerialNumber { get; set; }

    /// <summary>"Inserted" | "Removed"</summary>
    public string EventType { get; set; } = "Inserted";

    public DateTime EventUtc { get; set; } = DateTime.UtcNow;
}
