using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;

namespace EndpointSecurityAPI.Controllers
{
    [ApiController]
    [Route("api/file-risks")]
    [Authorize] // match whatever attribute/policy DevicesController uses
    public class FileRisksController : ControllerBase
    {
        private readonly AppDbContext _db;
        public FileRisksController(AppDbContext db) => _db = db;

        [HttpGet]
        public async Task<ActionResult<List<FileRiskRecordDto>>> GetAll(
            [FromQuery] string? riskLevel, [FromQuery] int? deviceId, [FromQuery] int take = 200)
        {
            var query = _db.FileRiskRecords.Include(f => f.Device).AsQueryable();

            if (!string.IsNullOrEmpty(riskLevel)) query = query.Where(f => f.RiskLevel == riskLevel);
            if (deviceId.HasValue) query = query.Where(f => f.DeviceId == deviceId.Value);

            var records = await query
                .OrderByDescending(f => f.DetectedAt)
                .Take(take)
                .Select(f => new FileRiskRecordDto
                {
                    Id = f.Id,
                    DeviceId = f.DeviceId,
                    DeviceName = f.Device != null ? f.Device.DeviceName : "Unknown",                    FileName = f.FileName,
                    FilePath = f.FilePath,
                    Extension = f.Extension,
                    Category = f.Category,
                    SizeBytes = f.SizeBytes,
                    Sha256 = f.Sha256,
                    FileCreatedUtc = f.FileCreatedUtc,
                    FileModifiedUtc = f.FileModifiedUtc,
                    Location = f.Location,
                    RiskLevel = f.RiskLevel,
                    RiskReasons = f.RiskReasons,
                    DetectedAt = f.DetectedAt
                })
                .ToListAsync();

            return Ok(records);
        }

        [HttpGet("summary")]
        public async Task<ActionResult<FileRiskSummaryDto>> GetSummary()
        {
            return Ok(new FileRiskSummaryDto
            {
                TotalFiles = await _db.FileRiskRecords.CountAsync(),
                HighRiskCount = await _db.FileRiskRecords.CountAsync(f => f.RiskLevel == "High"),
                MediumRiskCount = await _db.FileRiskRecords.CountAsync(f => f.RiskLevel == "Medium"),
                LowRiskCount = await _db.FileRiskRecords.CountAsync(f => f.RiskLevel == "Low")
            });
        }

        [HttpGet("device/{deviceId:int}")]
        public Task<ActionResult<List<FileRiskRecordDto>>> GetForDevice(int deviceId) => GetAll(null, deviceId, 500);
    }
}