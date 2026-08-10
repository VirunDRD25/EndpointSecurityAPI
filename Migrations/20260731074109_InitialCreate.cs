using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace EndpointSecurityAPI.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "admin_users",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    username = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    password_hash = table.Column<string>(type: "text", nullable: false),
                    role = table.Column<string>(type: "text", nullable: false),
                    created_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    last_login_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    is_active = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_admin_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "enrollment_tokens",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    label = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    token_hash = table.Column<string>(type: "text", nullable: false),
                    created_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    revoked_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    is_active = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_enrollment_tokens", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "system_settings",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    approved_software_json = table.Column<string>(type: "text", nullable: false),
                    trusted_wifi_ssids_json = table.Column<string>(type: "text", nullable: false),
                    risk_weights_json = table.Column<string>(type: "text", nullable: false),
                    alert_thresholds_json = table.Column<string>(type: "text", nullable: false),
                    updated_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_by = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_system_settings", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "devices",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    hardware_device_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    device_name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    username = table.Column<string>(type: "text", nullable: false),
                    windows_version = table.Column<string>(type: "text", nullable: false),
                    ip_address = table.Column<string>(type: "text", nullable: false),
                    mac_address = table.Column<string>(type: "text", nullable: false),
                    serial_number = table.Column<string>(type: "text", nullable: false),
                    department = table.Column<string>(type: "text", nullable: true),
                    first_enrolled_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    last_seen_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    current_risk_score = table.Column<int>(type: "integer", nullable: false),
                    enrolled_via_token_id = table.Column<int>(type: "integer", nullable: true),
                    is_active = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_devices", x => x.id);
                    table.ForeignKey(
                        name: "fk_devices_enrollment_tokens_enrolled_via_token_id",
                        column: x => x.enrolled_via_token_id,
                        principalTable: "enrollment_tokens",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "alerts",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    device_id = table.Column<int>(type: "integer", nullable: false),
                    type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    severity = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    message = table.Column<string>(type: "text", nullable: false),
                    created_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    is_resolved = table.Column<bool>(type: "boolean", nullable: false),
                    resolved_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    resolved_by = table.Column<string>(type: "text", nullable: true),
                    notification_sent = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_alerts", x => x.id);
                    table.ForeignKey(
                        name: "fk_alerts_devices_device_id",
                        column: x => x.device_id,
                        principalTable: "devices",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "download_events",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    device_id = table.Column<int>(type: "integer", nullable: false),
                    file_name = table.Column<string>(type: "text", nullable: false),
                    full_path = table.Column<string>(type: "text", nullable: false),
                    sha256 = table.Column<string>(type: "text", nullable: false),
                    is_digitally_signed = table.Column<bool>(type: "boolean", nullable: false),
                    publisher = table.Column<string>(type: "text", nullable: false),
                    file_type = table.Column<string>(type: "text", nullable: false),
                    source_folder = table.Column<string>(type: "text", nullable: false),
                    is_suspicious = table.Column<bool>(type: "boolean", nullable: false),
                    detected_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_download_events", x => x.id);
                    table.ForeignKey(
                        name: "fk_download_events_devices_device_id",
                        column: x => x.device_id,
                        principalTable: "devices",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "installed_software",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    device_id = table.Column<int>(type: "integer", nullable: false),
                    software_name = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    first_seen_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    last_seen_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    currently_installed = table.Column<bool>(type: "boolean", nullable: false),
                    is_unauthorized = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_installed_software", x => x.id);
                    table.ForeignKey(
                        name: "fk_installed_software_devices_device_id",
                        column: x => x.device_id,
                        principalTable: "devices",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "security_status_snapshots",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    device_id = table.Column<int>(type: "integer", nullable: false),
                    reported_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    firewall_domain_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    firewall_private_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    firewall_public_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    defender_antivirus_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    defender_real_time_protection_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    defender_definitions_status = table.Column<string>(type: "text", nullable: false),
                    defender_definition_age_days = table.Column<int>(type: "integer", nullable: false),
                    defender_status_read_successfully = table.Column<bool>(type: "boolean", nullable: false),
                    bit_locker_encrypted = table.Column<bool>(type: "boolean", nullable: false),
                    bit_locker_protection_status = table.Column<string>(type: "text", nullable: false),
                    bit_locker_encryption_percentage = table.Column<int>(type: "integer", nullable: false),
                    windows_update_last_installed_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    windows_update_pending_count = table.Column<int>(type: "integer", nullable: false),
                    windows_is_supported_version = table.Column<bool>(type: "boolean", nullable: false),
                    wifi_ssid = table.Column<string>(type: "text", nullable: true),
                    wifi_is_trusted = table.Column<bool>(type: "boolean", nullable: false),
                    wifi_signal_strength_percent = table.Column<int>(type: "integer", nullable: false),
                    risk_score = table.Column<int>(type: "integer", nullable: false),
                    risk_factors_json = table.Column<string>(type: "text", nullable: false),
                    unauthorized_software_json = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_security_status_snapshots", x => x.id);
                    table.ForeignKey(
                        name: "fk_security_status_snapshots_devices_device_id",
                        column: x => x.device_id,
                        principalTable: "devices",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "usb_events",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    device_id = table.Column<int>(type: "integer", nullable: false),
                    device_description = table.Column<string>(type: "text", nullable: false),
                    drive_letter = table.Column<string>(type: "text", nullable: true),
                    serial_number = table.Column<string>(type: "text", nullable: true),
                    event_type = table.Column<string>(type: "text", nullable: false),
                    event_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_usb_events", x => x.id);
                    table.ForeignKey(
                        name: "fk_usb_events_devices_device_id",
                        column: x => x.device_id,
                        principalTable: "devices",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "system_settings",
                columns: new[] { "id", "alert_thresholds_json", "approved_software_json", "risk_weights_json", "trusted_wifi_ssids_json", "updated_by", "updated_utc" },
                values: new object[] { 1, "{\"HighRiskThreshold\":50,\"StaleDeviceMinutes\":30}", "[]", "{\"FirewallDisabled\":20,\"DefenderDisabled\":30,\"RealtimeProtectionDisabled\":15,\"DefinitionsOutdated\":10,\"BitLockerOff\":15,\"UnapprovedUsbConnected\":15,\"UnauthorizedSoftware\":25,\"SuspiciousDownload\":25,\"UntrustedWifi\":10,\"WindowsUpdatesPending\":10,\"UnsupportedWindowsVersion\":20}", "[]", null, new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc) });

            migrationBuilder.CreateIndex(
                name: "ix_admin_users_username",
                table: "admin_users",
                column: "username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_alerts_device_id_is_resolved_created_utc",
                table: "alerts",
                columns: new[] { "device_id", "is_resolved", "created_utc" });

            migrationBuilder.CreateIndex(
                name: "ix_devices_enrolled_via_token_id",
                table: "devices",
                column: "enrolled_via_token_id");

            migrationBuilder.CreateIndex(
                name: "ix_devices_hardware_device_id",
                table: "devices",
                column: "hardware_device_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_download_events_device_id_detected_utc",
                table: "download_events",
                columns: new[] { "device_id", "detected_utc" });

            migrationBuilder.CreateIndex(
                name: "ix_installed_software_device_id_software_name",
                table: "installed_software",
                columns: new[] { "device_id", "software_name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_security_status_snapshots_device_id_reported_utc",
                table: "security_status_snapshots",
                columns: new[] { "device_id", "reported_utc" });

            migrationBuilder.CreateIndex(
                name: "ix_usb_events_device_id_event_utc",
                table: "usb_events",
                columns: new[] { "device_id", "event_utc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "admin_users");

            migrationBuilder.DropTable(
                name: "alerts");

            migrationBuilder.DropTable(
                name: "download_events");

            migrationBuilder.DropTable(
                name: "installed_software");

            migrationBuilder.DropTable(
                name: "security_status_snapshots");

            migrationBuilder.DropTable(
                name: "system_settings");

            migrationBuilder.DropTable(
                name: "usb_events");

            migrationBuilder.DropTable(
                name: "devices");

            migrationBuilder.DropTable(
                name: "enrollment_tokens");
        }
    }
}
