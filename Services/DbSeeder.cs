using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Services;

public static class DbSeeder
{
    /// <summary>
    /// Applies pending EF Core migrations and seeds a default admin account
    /// on first run. Logs the generated password ONCE — change it
    /// immediately via the (future) change-password endpoint or directly in
    /// the database.
    /// </summary>
    public static async Task MigrateAndSeedAsync(IServiceProvider services, ILogger logger)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var config = scope.ServiceProvider.GetRequiredService<IConfiguration>();

        await db.Database.MigrateAsync();

        if (!await db.AdminUsers.AnyAsync())
        {
            var defaultUsername = config["DefaultAdmin:Username"] ?? "admin";
            var defaultPassword = config["DefaultAdmin:Password"];

            if (string.IsNullOrWhiteSpace(defaultPassword))
            {
                defaultPassword = Guid.NewGuid().ToString("N")[..12];
                logger.LogWarning(
                    "No DefaultAdmin:Password configured — generated a random one-time password for user '{User}': {Password}. " +
                    "Log in and change it immediately; this will not be shown again.",
                    defaultUsername, defaultPassword);
            }

            db.AdminUsers.Add(new AdminUser
            {
                Username = defaultUsername,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(defaultPassword),
                Role = "Admin",
                CreatedUtc = DateTime.UtcNow
            });

            await db.SaveChangesAsync();
            logger.LogInformation("Seeded default admin account '{User}'", defaultUsername);
        }
    }
}
