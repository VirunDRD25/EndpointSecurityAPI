using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace EndpointSecurityAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddBrowserExtensionMonitoring : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "blacklisted_extensions_json",
                table: "system_settings",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "required_security_extensions_json",
                table: "system_settings",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateTable(
                name: "browser_extensions",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    device_id = table.Column<int>(type: "integer", nullable: false),
                    browser = table.Column<string>(type: "text", nullable: false),
                    profile = table.Column<string>(type: "text", nullable: false),
                    extension_id = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    name = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    version = table.Column<string>(type: "text", nullable: false),
                    publisher = table.Column<string>(type: "text", nullable: false),
                    permissions_json = table.Column<string>(type: "text", nullable: false),
                    is_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    is_from_web_store = table.Column<bool>(type: "boolean", nullable: false),
                    is_developer_mode = table.Column<bool>(type: "boolean", nullable: false),
                    is_blacklisted = table.Column<bool>(type: "boolean", nullable: false),
                    has_dangerous_permissions = table.Column<bool>(type: "boolean", nullable: false),
                    installed_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    first_seen_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    last_seen_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    currently_installed = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_browser_extensions", x => x.id);
                    table.ForeignKey(
                        name: "fk_browser_extensions_devices_device_id",
                        column: x => x.device_id,
                        principalTable: "devices",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.UpdateData(
                table: "system_settings",
                keyColumn: "id",
                keyValue: 1,
                columns: new[] { "blacklisted_extensions_json", "required_security_extensions_json", "risk_weights_json" },
                values: new object[] { "[]", "[]", "{\"FirewallDisabled\":20,\"DefenderDisabled\":30,\"RealtimeProtectionDisabled\":15,\"DefinitionsOutdated\":10,\"BitLockerOff\":15,\"UnapprovedUsbConnected\":15,\"UnauthorizedSoftware\":25,\"SuspiciousDownload\":25,\"UntrustedWifi\":10,\"WindowsUpdatesPending\":10,\"UnsupportedWindowsVersion\":20,\"BlacklistedExtension\":25,\"UnknownPublisherExtension\":10,\"DeveloperModeExtension\":30,\"SecurityExtensionRemoved\":20,\"DangerousExtensionPermissions\":10}" });

            migrationBuilder.CreateIndex(
                name: "ix_browser_extensions_device_id_browser_profile_extension_id",
                table: "browser_extensions",
                columns: new[] { "device_id", "browser", "profile", "extension_id" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "browser_extensions");

            migrationBuilder.DropColumn(
                name: "blacklisted_extensions_json",
                table: "system_settings");

            migrationBuilder.DropColumn(
                name: "required_security_extensions_json",
                table: "system_settings");

            migrationBuilder.UpdateData(
                table: "system_settings",
                keyColumn: "id",
                keyValue: 1,
                column: "risk_weights_json",
                value: "{\"FirewallDisabled\":20,\"DefenderDisabled\":30,\"RealtimeProtectionDisabled\":15,\"DefinitionsOutdated\":10,\"BitLockerOff\":15,\"UnapprovedUsbConnected\":15,\"UnauthorizedSoftware\":25,\"SuspiciousDownload\":25,\"UntrustedWifi\":10,\"WindowsUpdatesPending\":10,\"UnsupportedWindowsVersion\":20}");
        }
    }
}
