using System.Text;
using EndpointSecurityAPI.Auth;
using EndpointSecurityAPI.Data;
using EndpointSecurityAPI.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// ---------- Database (PostgreSQL via Supabase) ----------
var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("ConnectionStrings:Default is not configured.");

builder.Services.AddDbContext<AppDbContext>(options =>
    options
        .UseNpgsql(connectionString)
        // Supabase's table editor, auto-generated REST API, and SQL editor
        // all assume snake_case table/column names. Without this, EF Core
        // creates PascalCase identifiers that need double-quoting in every
        // raw SQL query and look inconsistent next to Supabase's own tables.
        .UseSnakeCaseNamingConvention());

// ---------- Authentication: two schemes ----------
// "Bearer" (JWT)   -> used by the admin dashboard (React/ASP.NET) after /api/auth/login
// "DeviceToken"    -> used by the Windows Agent when posting to /api/device/report
var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtKey = jwtSection["Key"] ?? throw new InvalidOperationException("Jwt:Key is not configured.");

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSection["Issuer"],
            ValidAudience = jwtSection["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    })
    .AddScheme<DeviceTokenAuthOptions, DeviceTokenAuthenticationHandler>(
        DeviceTokenDefaults.AuthenticationScheme, _ => { });

builder.Services.AddAuthorization();

// ---------- App services ----------
builder.Services.AddScoped<ReportIngestionService>();
builder.Services.AddScoped<AlertService>();
builder.Services.AddScoped<JwtTokenService>();
builder.Services.AddScoped<SystemSettingsProvider>();
builder.Services.AddScoped<SoftwareReauthorizationService>();
builder.Services.AddScoped<RiskScoreRecomputeService>();
builder.Services.AddHostedService<StaleDeviceCheckService>();

// ---------- MVC / Swagger ----------
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new() { Title = "Endpoint Security API", Version = "v1" });

    // Let Swagger UI send a Bearer token (works for both JWT admin calls and
    // DeviceToken agent calls, since both use the Authorization: Bearer header)
    options.AddSecurityDefinition("Bearer", new()
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter: Bearer {token}"
    });
    options.AddSecurityRequirement(new()
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ---------- CORS for the React admin dashboard ----------
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("DashboardPolicy", policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

// ---------- Migrate DB + seed default admin on startup ----------
await DbSeeder.MigrateAndSeedAsync(app.Services, app.Logger);

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("DashboardPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
