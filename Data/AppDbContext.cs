using EndpointSecurityAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Device> Devices => Set<Device>();
    public DbSet<SecurityStatusSnapshot> SecurityStatusSnapshots => Set<SecurityStatusSnapshot>();
    public DbSet<InstalledSoftwareRecord> InstalledSoftware => Set<InstalledSoftwareRecord>();
    public DbSet<BrowserExtensionRecord> BrowserExtensions => Set<BrowserExtensionRecord>();
    public DbSet<DownloadEvent> DownloadEvents => Set<DownloadEvent>();
    public DbSet<UsbEventRecord> UsbEvents => Set<UsbEventRecord>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<AdminUser> AdminUsers => Set<AdminUser>();
    public DbSet<SystemSettings> SystemSettings => Set<SystemSettings>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Device>(e =>
        {
            e.HasIndex(d => d.HardwareDeviceId).IsUnique();
            e.Property(d => d.HardwareDeviceId).HasMaxLength(128).IsRequired();
            e.Property(d => d.DeviceName).HasMaxLength(255);
            e.HasOne(d => d.EnrolledViaToken)
                .WithMany(t => t.EnrolledDevices)
                .HasForeignKey(d => d.EnrolledViaTokenId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<SecurityStatusSnapshot>(e =>
        {
            e.HasIndex(s => new { s.DeviceId, s.ReportedUtc });
            e.HasOne(s => s.Device)
                .WithMany(d => d.Snapshots)
                .HasForeignKey(s => s.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<InstalledSoftwareRecord>(e =>
        {
            e.HasIndex(s => new { s.DeviceId, s.SoftwareName }).IsUnique();
            e.Property(s => s.SoftwareName).HasMaxLength(500);
            e.HasOne(s => s.Device)
                .WithMany(d => d.InstalledSoftware)
                .HasForeignKey(s => s.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<BrowserExtensionRecord>(e =>
        {
            e.HasIndex(x => new { x.DeviceId, x.Browser, x.Profile, x.ExtensionId }).IsUnique();
            e.Property(x => x.Name).HasMaxLength(500);
            e.Property(x => x.ExtensionId).HasMaxLength(200);
            e.HasOne(x => x.Device)
                .WithMany()
                .HasForeignKey(x => x.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<DownloadEvent>(e =>
        {
            e.HasIndex(d => new { d.DeviceId, d.DetectedUtc });
            e.HasOne(d => d.Device)
                .WithMany(dev => dev.DownloadEvents)
                .HasForeignKey(d => d.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<UsbEventRecord>(e =>
        {
            e.HasIndex(u => new { u.DeviceId, u.EventUtc });
            e.HasOne(u => u.Device)
                .WithMany(dev => dev.UsbEvents)
                .HasForeignKey(u => u.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Alert>(e =>
        {
            e.HasIndex(a => new { a.DeviceId, a.IsResolved, a.CreatedUtc });
            e.Property(a => a.Type).HasConversion<string>().HasMaxLength(50);
            e.Property(a => a.Severity).HasConversion<string>().HasMaxLength(20);
            e.HasOne(a => a.Device)
                .WithMany(d => d.Alerts)
                .HasForeignKey(a => a.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<EnrollmentToken>(e =>
        {
            e.Property(t => t.Label).HasMaxLength(255);
        });

        modelBuilder.Entity<AdminUser>(e =>
        {
            e.HasIndex(u => u.Username).IsUnique();
            e.Property(u => u.Username).HasMaxLength(100);
        });

        modelBuilder.Entity<SystemSettings>(e =>
        {
            e.HasData(new SystemSettings
            {
                Id = 1,
                ApprovedSoftwareJson = "[]",
                TrustedWifiSsidsJson = "[]",
                BlacklistedExtensionsJson = "[]",
                RequiredSecurityExtensionsJson = "[]",
                // NOTE: must be real default values, not "{}" — deserializing
                // "{}" into these DTOs succeeds (doesn't return null), so it
                // silently produces HighRiskThreshold=0/StaleDeviceMinutes=0
                // and every risk weight=0 until an admin visits the
                // Configuration page and saves. These literals must stay in
                // sync with RiskWeightsDto/AlertThresholdsDto's property
                // names — see Dtos/SettingsDtos.cs.
                RiskWeightsJson = "{\"FirewallDisabled\":20,\"DefenderDisabled\":30,\"RealtimeProtectionDisabled\":15,\"DefinitionsOutdated\":10,\"BitLockerOff\":15,\"UnapprovedUsbConnected\":15,\"UnauthorizedSoftware\":25,\"SuspiciousDownload\":25,\"UntrustedWifi\":10,\"WindowsUpdatesPending\":10,\"UnsupportedWindowsVersion\":20,\"BlacklistedExtension\":25,\"UnknownPublisherExtension\":10,\"DeveloperModeExtension\":30,\"SecurityExtensionRemoved\":20,\"DangerousExtensionPermissions\":10}",
                AlertThresholdsJson = "{\"HighRiskThreshold\":50,\"StaleDeviceMinutes\":30}",
                UpdatedUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            });
        });

        // ---- PostgreSQL-specific: force every DateTime column to timestamptz ----
        // Every DateTime in this codebase is DateTime.UtcNow (Kind=Utc).
        // Npgsql's default mapping for a plain `DateTime` property is
        // "timestamp without time zone", which only accepts Kind=Unspecified
        // values — writing a Kind=Utc value to it throws at SaveChanges time.
        // "timestamp with time zone" (timestamptz) is the correct Postgres
        // type for storing UTC instants and accepts Kind=Utc directly.
        // (MySQL's DATETIME didn't enforce Kind at all, so this wasn't
        // needed before switching providers.)
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entityType.GetProperties())
            {
                if (property.ClrType == typeof(DateTime) || property.ClrType == typeof(DateTime?))
                {
                    property.SetColumnType("timestamp with time zone");
                }
            }
        }
    }
}
