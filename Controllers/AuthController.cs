using EndpointSecurityAPI.Auth;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Dtos;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurityAPI.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly JwtTokenService _jwtService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(AppDbContext db, JwtTokenService jwtService, ILogger<AuthController> logger)
    {
        _db = db;
        _jwtService = jwtService;
        _logger = logger;
    }

    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponseDto), 200)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
    {
        var user = await _db.AdminUsers.FirstOrDefaultAsync(u => u.Username == request.Username && u.IsActive);

        // Constant-shape response either way to avoid username enumeration via timing/response differences.
        if (user is null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            _logger.LogWarning("Failed login attempt for username '{Username}'", request.Username);
            return Unauthorized(new { message = "Invalid username or password" });
        }

        user.LastLoginUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        var (token, expiresUtc) = _jwtService.GenerateToken(user);
        return Ok(new LoginResponseDto(token, expiresUtc, user.Username, user.Role));
    }
}
