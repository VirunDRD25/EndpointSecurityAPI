namespace EndpointSecurityAPI.Dtos
{
    public class FileRiskRecordDto
    {
        public int Id { get; set; }
        public int DeviceId { get; set; }
        public string DeviceName { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Extension { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public long SizeBytes { get; set; }
        public string Sha256 { get; set; } = string.Empty;
        public DateTime FileCreatedUtc { get; set; }
        public DateTime FileModifiedUtc { get; set; }
        public string Location { get; set; } = string.Empty;
        public string RiskLevel { get; set; } = string.Empty;
        public string[] RiskReasons { get; set; } = Array.Empty<string>();
        public DateTime DetectedAt { get; set; }
    }

    public class FileRiskSummaryDto
    {
        public int TotalFiles { get; set; }
        public int HighRiskCount { get; set; }
        public int MediumRiskCount { get; set; }
        public int LowRiskCount { get; set; }
    }
}