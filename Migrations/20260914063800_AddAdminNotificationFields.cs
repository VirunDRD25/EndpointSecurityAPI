using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EndpointSecurityAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddAdminNotificationFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "email",
                table: "admin_users",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "notifications_muted",
                table: "admin_users",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "email",
                table: "admin_users");

            migrationBuilder.DropColumn(
                name: "notifications_muted",
                table: "admin_users");
        }
    }
}
