namespace EndpointSecurityAPI.Entities;

public class DownloadEvent
{
    public int Id { get; set; }

    public int DeviceId { get; set; }
    public Device? Device { get; set; }

    public string FileName { get; set; } = string.Empty;
    public string FullPath { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public bool IsDigitallySigned { get; set; }
    public string Publisher { get; set; } = "Unknown";
    public string FileType { get; set; } = string.Empty;
    public string SourceFolder { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }

    public DateTime DetectedUtc { get; set; } = DateTime.UtcNow;
}
