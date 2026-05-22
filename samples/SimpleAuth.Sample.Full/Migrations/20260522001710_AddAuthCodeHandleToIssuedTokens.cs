using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SimpleAuth.Sample.Full.Migrations;

/// <inheritdoc />
public partial class AddAuthCodeHandleToIssuedTokens : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "AuthorizationCodeHandle",
            table: "IssuedTokens",
            type: "TEXT",
            maxLength: 200,
            nullable: true);

        migrationBuilder.CreateIndex(
            name: "IX_IssuedTokens_AuthorizationCodeHandle",
            table: "IssuedTokens",
            column: "AuthorizationCodeHandle");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(
            name: "IX_IssuedTokens_AuthorizationCodeHandle",
            table: "IssuedTokens");

        migrationBuilder.DropColumn(
            name: "AuthorizationCodeHandle",
            table: "IssuedTokens");
    }
}
