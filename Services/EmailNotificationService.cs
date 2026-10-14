using System.Net;
using System.Net.Mail;
using EndpointSecurityAPI.Auth;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Services;

/// <summary>
/// Watches for HighRiskScore alerts that haven't been emailed yet
/// (Alert.NotificationSent == false) and sends an email to every active
/// Admin/Cybersecurity-Team user who has an email on file and hasn't
/// muted notifications. Runs on its own timer, separate from AlertService
/// (which only creates/updates alert rows) and separate from the 5-minute
/// agent report cycle, so a slow/failed SMTP send never blocks device
/// report ingestion.
/// </summary>
public class EmailNotificationService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly IConfiguration _config;
    private readonly ILogger<EmailNotificationService> _logger;
    private static readonly string[] NotifiableRoles = AppRoles.ManagementRoles.Split(',');
    private readonly TimeSpan _pollInterval = TimeSpan.FromMinutes(1);

    public EmailNotificationService(IServiceProvider services, IConfiguration config, ILogger<EmailNotificationService> logger)
    {
        _services = services;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Small startup delay so this doesn't race DbSeeder's migration on cold start.
        await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SendPendingNotificationsAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Email notification sweep failed");
            }

            try { await Task.Delay(_pollInterval, stoppingToken); } catch (TaskCanceledException) { }
        }
    }

    private async Task SendPendingNotificationsAsync(CancellationToken ct)
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var pendingAlerts = await db.Alerts
            .Include(a => a.Device)
            .Where(a => a.Type == AlertType.HighRiskScore && !a.NotificationSent)
            .ToListAsync(ct);

        if (pendingAlerts.Count == 0) return;

        var recipients = await db.AdminUsers
            .Where(u => u.IsActive
                && !u.NotificationsMuted
                && u.Email != null && u.Email != ""
                && NotifiableRoles.Contains(u.Role))
            .Select(u => u.Email!)
            .ToListAsync(ct);

        foreach (var alert in pendingAlerts)
        {
            if (recipients.Count > 0)
            {
                try
                {
                    await SendEmailAsync(recipients, alert, ct);
                    _logger.LogInformation("Sent high-risk notification for device {DeviceId} to {Count} recipient(s)",
                        alert.DeviceId, recipients.Count);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed sending high-risk email for alert {AlertId} — will retry next sweep", alert.Id);
                    continue; // leave NotificationSent = false so it retries next cycle
                }
            }
            else
            {
                _logger.LogWarning("High-risk alert {AlertId} has no eligible email recipients (check admin emails / mute settings)", alert.Id);
            }

            alert.NotificationSent = true;
        }

        await db.SaveChangesAsync(ct);
    }

    private async Task SendEmailAsync(List<string> recipients, Alert alert, CancellationToken ct)
    {
        
        var smtp = _config.GetSection("Smtp");

        string host = smtp["Host"]
            ?? throw new InvalidOperationException("Smtp:Host is not configured.");

        int port = int.TryParse(smtp["Port"], out var p) ? p : 587;

        bool enableSsl = !bool.TryParse(smtp["EnableSsl"], out var ssl) || ssl;

        string username = smtp["Username"] ?? "";
        string password = smtp["Password"] ?? "";
        string fromAddress = smtp["FromAddress"] ?? username;
        string fromName = smtp["FromName"] ?? "Endpoint Security Alerts";

if (string.IsNullOrWhiteSpace(username))
    throw new InvalidOperationException("Smtp:Username is not configured.");

if (string.IsNullOrWhiteSpace(password))
    throw new InvalidOperationException("Smtp:Password is not configured.");

if (string.IsNullOrWhiteSpace(fromAddress))
    throw new InvalidOperationException("Smtp:FromAddress is not configured.");


        if (!string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
            throw new InvalidOperationException(
            "Smtp:Username is set but Smtp:Password is empty — check user-secrets or the Smtp__Password environment variable.");

        string deviceName = alert.Device?.DeviceName ?? $"Device #{alert.DeviceId}";

        using var message = new MailMessage
        {
            From = new MailAddress(fromAddress, fromName),
            Subject = $"[Critical] High risk score on {deviceName}",
            Body = BuildEmailBody(deviceName, alert),
            IsBodyHtml = true
        };
        foreach (var to in recipients) message.To.Add(to);

        using var client = new SmtpClient(host, port)
        {
            EnableSsl = enableSsl,
            Credentials = string.IsNullOrEmpty(username) ? null : new NetworkCredential(username, password)
        };

        await client.SendMailAsync(message, ct);
    }

    private static string BuildEmailBody(string deviceName, Alert alert)
    {
        // alert.Message looks like:
        // "Device risk score reached 72 (threshold: 50). Contributing factors: Firewall disabled...; BitLocker not enabled..."
        const string marker = "Contributing factors: ";
        var idx = alert.Message.IndexOf(marker, StringComparison.Ordinal);
        string summary = idx >= 0 ? alert.Message[..idx].Trim() : alert.Message;
        string factorsPart = idx >= 0 ? alert.Message[(idx + marker.Length)..] : "";

        var factors = factorsPart.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var factorsHtml = factors.Length > 0
            ? string.Join("", factors.Select(f => $"<li>{WebUtility.HtmlEncode(f)}</li>"))
            : "<li>No specific contributing factors were recorded.</li>";

        return $@"
            <div style=""font-family:Arial,sans-serif;font-size:14px;color:#222;"">
                <h2 style=""color:#c0392b;"">High risk score detected</h2>
                <p><strong>Device:</strong> {WebUtility.HtmlEncode(deviceName)}</p>
                <p><strong>Detected:</strong> {alert.CreatedUtc:u} UTC</p>
                <p>{WebUtility.HtmlEncode(summary)}</p>
                <p><strong>Contributing issues:</strong></p>
                <ul>{factorsHtml}</ul>
                <p style=""color:#888;font-size:12px;"">
                    You're receiving this because your admin account is subscribed to high-risk alerts.
                    You can mute these in the dashboard under Users → My Notification Settings.
                </p>
            </div>";
    }
}