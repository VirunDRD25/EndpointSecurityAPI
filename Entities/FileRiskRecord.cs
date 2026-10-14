namespace EndpointSecurityAPI.Entities
{
    public class FileRiskRecord
    {
        public int Id { get; set; }
        public int DeviceId { get; set; }
        public Device? Device { get; set; }
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Extension { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public long SizeBytes { get; set; }
        public string Sha256 { get; set; } = string.Empty;
        public DateTime FileCreatedUtc { get; set; }
        public DateTime FileModifiedUtc { get; set; }
        public string Location { get; set; } = string.Empty;
        public string RiskLevel { get; set; } = "Low";
        public string[] RiskReasons { get; set; } = Array.Empty<string>(); // maps to Postgres text[] via Npgsql
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    }
}