using System.Security.Claims;
using System.Text.Encodings.Web;
using EndpointSecurityAPI.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace EndpointSecurityAPI.Auth;

public class DeviceTokenAuthOptions : AuthenticationSchemeOptions { }

public class DeviceTokenAuthenticationHandler : AuthenticationHandler<DeviceTokenAuthOptions>
{
    private readonly AppDbContext _db;

    public DeviceTokenAuthenticationHandler(
        IOptionsMonitor<DeviceTokenAuthOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        AppDbContext db)
        : base(options, logger, encoder)
    {
        _db = db;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authHeader))
            return AuthenticateResult.Fail("Missing Authorization header");

        var headerValue = authHeader.ToString();
        if (!headerValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.Fail("Authorization header must use the Bearer scheme");

        var rawToken = headerValue["Bearer ".Length..].Trim();
        if (string.IsNullOrWhiteSpace(rawToken))
            return AuthenticateResult.Fail("Empty bearer token");

        Logger.LogInformation("DeviceToken: received token starting with '{Prefix}' (length={Len})",
            rawToken[..Math.Min(8, rawToken.Length)], rawToken.Length);

        var activeTokens = await _db.EnrollmentTokens
            .Where(t => t.IsActive)
            .ToListAsync();

        Logger.LogInformation("DeviceToken: {Count} active enrollment token(s) found in DB", activeTokens.Count);

        foreach (var t in activeTokens)
        {
            Logger.LogInformation("DeviceToken: checking id={Id} label='{Label}' hashPrefix='{HashPrefix}'",
                t.Id, t.Label, t.TokenHash[..Math.Min(15, t.TokenHash.Length)]);

            bool match = BCrypt.Net.BCrypt.Verify(rawToken, t.TokenHash);
            Logger.LogInformation("DeviceToken: BCrypt.Verify result = {Match}", match);

            if (match)
            {
                var claims = new[]
                {
                    new Claim("EnrollmentTokenId", t.Id.ToString()),
                    new Claim(ClaimTypes.Name, $"agent-via-token-{t.Id}")
                };
                var identity = new ClaimsIdentity(claims, DeviceTokenDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, DeviceTokenDefaults.AuthenticationScheme);
                Logger.LogInformation("DeviceToken: authentication SUCCESS for token id={Id}", t.Id);
                return AuthenticateResult.Success(ticket);
            }
        }

        Logger.LogWarning("DeviceToken: no token matched — returning 401");
        return AuthenticateResult.Fail("Invalid or revoked enrollment token");
    }
}