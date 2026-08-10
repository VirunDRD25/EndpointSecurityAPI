# Endpoint Security API — Phase 2

ASP.NET Core 8 Web API that receives reports from the Phase 1 Windows Agent,
stores them in PostgreSQL (via Supabase), generates alerts, and exposes everything the Phase 4
admin dashboard needs.

## How this lines up with your plan

| Plan item | Where |
|---|---|
| `/api/device/report` | `Controllers/DeviceReportController.cs` |
| JWT authentication | `Auth/JwtTokenService.cs` + `Controllers/AuthController.cs` (admin dashboard) |
| HTTPS | enforced via `app.UseHttpsRedirection()` in `Program.cs`; run behind a real cert in production (see below) |
| PostgreSQL (Supabase) | `Data/AppDbContext.cs` via Npgsql.EntityFrameworkCore.PostgreSQL |
| Devices / Security Status / Alerts / Installed Software (Phase 3 tables) | `Entities/*.cs` — this *is* the Phase 3 DB design, expressed as EF Core code-first models |
| Dashboard endpoints (Phase 4 backend) | `Controllers/DevicesController.cs`, `AlertsController.cs`, `DashboardController.cs` |
| Automatic alerts (Phase 5) | `Services/AlertService.cs` generates alerts server-side on every report; `Services/StaleDeviceCheckService.cs` covers "hasn't reported in for a defined period." Each `Alert` has a `NotificationSent` flag — Phase 5 adds an email-sending background service that watches for `NotificationSent == false` and dispatches, marking it sent. Not built yet since you asked to complete Phase 2 first. |

## Design decision: enrollment tokens, not per-device tokens

Your Phase 1 agent has one static `ApiKeyOrDeviceToken` value in
`appsettings.json`. Generating a unique token per laptop would mean
hand-editing that file before installing on every single machine — not
realistic for a mass rollout via GPO/SCCM.

Instead: admins create one or more **enrollment tokens** from the dashboard
(e.g. one per office/department), bake the same token into every agent's
config for that batch, and the server tells devices apart using the
hardware UUID your agent already sends as `deviceId`. First report from a
new UUID auto-registers the device. If a token leaks, revoke it — devices
already enrolled keep working, only future enrollments with that token stop.

## Requirements

- .NET 8 SDK
- A [Supabase](https://supabase.com) project (free tier is fine to start)
- `dotnet-ef` CLI tool: `dotnet tool install --global dotnet-ef`

## 1. Get your Supabase connection string

In the Supabase dashboard: **Project Settings → Database → Connection string**.

Supabase gives you two pooling modes on port `6543` (Transaction) and `5432`
(Session), plus a direct connection. **Use the Session pooler (or direct
connection), not the Transaction pooler**, for this API:

- EF Core relies on prepared statements and multi-statement transactions
  (migrations, `SaveChanges` batching). PgBouncer's *transaction* pooling
  mode breaks prepared statement caching and can cause hard-to-diagnose
  errors under load.
- The *session* pooler (port `5432`) behaves like a normal Postgres
  connection and works with EF Core out of the box.
- A long-running ASP.NET Core service (not a serverless function) doesn't
  need the aggressive connection reuse the transaction pooler is designed
  for anyway — a small session pool is fine.

Copy the connection details into `appsettings.json` → `ConnectionStrings:Default`
(format shown there uses Npgsql's key=value syntax, not a `postgres://` URI —
convert if Supabase shows you the URI form: `Host`, `Port`, `Database`,
`Username`, `Password` map directly; add `SSL Mode=Require;Trust Server Certificate=true;`).

## 2. Configure secrets

In `appsettings.json` (or better, `dotnet user-secrets` for local dev):

- `Jwt:Key` — replace with a random 32+ character secret (`openssl rand -base64 32`)
- `DefaultAdmin:Password` — set this, or leave blank and read the
  auto-generated one-time password from the console log on first run
- `Cors:AllowedOrigins` — add your Phase 4 React dashboard's URL

## 3. Build, migrate, run

```powershell
cd EndpointSecurityAPI
dotnet restore
dotnet ef migrations add InitialCreate
dotnet ef database update
dotnet run
```

Swagger UI opens at `https://localhost:5001/swagger` in Development mode.

Migrations also run automatically at startup (`DbSeeder.MigrateAndSeedAsync`
calls `db.Database.MigrateAsync()`), so `dotnet ef database update` is only
needed once initially / after adding new migrations.

**Note on table names:** the DbContext uses `EFCore.NamingConventions`'
snake_case convention, so EF creates tables like `devices`,
`security_status_snapshots`, `enrollment_tokens` — matching what you'll see
if you also browse the schema in Supabase's Table Editor, rather than
PascalCase names that would need quoting in Supabase's SQL editor.

**Note on Row Level Security (RLS):** tables created via EF Core migrations
do **not** have RLS enabled by default (Supabase only auto-enables it for
tables created through its own dashboard). Since this API is the sole
gatekeeper to the data — it already has its own JWT/DeviceToken auth layer —
that's intentional: don't expose these tables through Supabase's
auto-generated REST/GraphQL API unless you also design RLS policies for
them; otherwise anyone with the anon key could bypass your API's auth
entirely and query the tables directly.

## 4. Walkthrough

**Admin logs in:**
```bash
curl -k -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<the password from step 2/console log>"}'
```
Returns a JWT — use it as `Authorization: Bearer <token>` for every
`/api/devices`, `/api/alerts`, `/api/dashboard`, `/api/enrollment-tokens` call below.

**Admin creates an enrollment token:**
```bash
curl -k -X POST https://localhost:5001/api/enrollment-tokens \
  -H "Authorization: Bearer <admin JWT>" \
  -H "Content-Type: application/json" \
  -d '{"label":"Colombo Office"}'
```
Copy the `rawToken` from the response into the agent's `appsettings.json` →
`AgentSettings:ApiKeyOrDeviceToken`, and set `AgentSettings:ServerBaseUrl`
to `https://your-server:5001/`.

**Agent reports (this is what Phase 1's `ApiClient.cs` does automatically):**
```bash
curl -k -X POST https://localhost:5001/api/device/report \
  -H "Authorization: Bearer <rawToken from above>" \
  -H "Content-Type: application/json" \
  -d '{ "deviceId":"...", "deviceName":"PC-025", "riskScore":45, "firewall":{...}, "defender":{...}, ... }'
```

**Admin views the fleet:**
```bash
curl -k https://localhost:5001/api/devices -H "Authorization: Bearer <admin JWT>"
curl -k https://localhost:5001/api/dashboard/summary -H "Authorization: Bearer <admin JWT>"
curl -k https://localhost:5001/api/alerts?resolved=false -H "Authorization: Bearer <admin JWT>"
```

## Endpoints added for Phase 4

The dashboard needed a few things the API didn't expose yet:

| Endpoint | Purpose |
|---|---|
| `GET/PUT /api/settings` | Configuration Management page — approved software, trusted Wi-Fi, risk weights, alert thresholds |
| `GET /api/dashboard/critical-devices` | Dashboard's "Critical Alerts" widget — devices with open issues, short bullet list per device |
| `PATCH /api/devices/{id}` | Assign a Department to a device from its detail page (agents can't know org structure) |
| `GET/POST/PATCH /api/admin-users` | "User permissions" — manage who can log into the dashboard and their role |
| `GET /api/device/config` | Agent-facing; lets an agent pull centrally-managed config instead of local files. **Not yet called by the Phase 1 agent** — see its README. |

Also: `/api/dashboard/summary` now returns per-tier (`lowRiskCount`/`mediumRiskCount`/`highRiskCount`) counts instead of a single `highRiskDevices` number, to match the dashboard's Low/Medium/High breakdown widget. Every threshold that used to be read from static `appsettings.json` (`AlertService`, `DevicesController`, `DashboardController`, `StaleDeviceCheckService`) now reads live from the `system_settings` table via `SystemSettingsProvider`, so editing thresholds on the Configuration page takes effect without a restart.

## Production hardening notes

- **HTTPS**: `UseHttpsRedirection()` is on, but you need a real TLS
  certificate bound to the host (IIS/Kestrel + Let's Encrypt, or terminate
  TLS at a reverse proxy like nginx/Caddy in front of Kestrel).
- **JWT key**: never ship the placeholder key in `appsettings.json` to
  production — use environment variables, `dotnet user-secrets`, or a
  secrets manager (Azure Key Vault, AWS Secrets Manager, etc).
- **Rate limiting**: `/api/auth/login` and `/api/device/report` have no
  rate limiting yet — add `Microsoft.AspNetCore.RateLimiting` before
  exposing this to the internet.
- **Enrollment token exposure**: the raw token is only ever shown once,
  right after creation — if you lose it, revoke and issue a new one, you
  cannot retrieve the original value again (only its BCrypt hash is stored).
- **CORS**: currently allowlists specific origins for the dashboard;
  double check this before deploying Phase 4.
