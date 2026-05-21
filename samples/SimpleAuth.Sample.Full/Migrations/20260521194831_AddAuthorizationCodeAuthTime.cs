using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SimpleAuth.Sample.Full.Migrations;

/// <inheritdoc />
public partial class AddAuthorizationCodeAuthTime : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "DPopJkt",
            table: "RefreshTokens",
            type: "TEXT",
            maxLength: 128,
            nullable: true);

        migrationBuilder.AlterColumn<string>(
            name: "CodeChallengeMethod",
            table: "ParEntries",
            type: "TEXT",
            maxLength: 10,
            nullable: true,
            oldClrType: typeof(string),
            oldType: "TEXT",
            oldMaxLength: 10);

        migrationBuilder.AlterColumn<string>(
            name: "CodeChallenge",
            table: "ParEntries",
            type: "TEXT",
            maxLength: 256,
            nullable: true,
            oldClrType: typeof(string),
            oldType: "TEXT",
            oldMaxLength: 256);

        migrationBuilder.AlterColumn<string>(
            name: "CodeChallenge",
            table: "AuthorizationCodes",
            type: "TEXT",
            maxLength: 256,
            nullable: true,
            oldClrType: typeof(string),
            oldType: "TEXT",
            oldMaxLength: 256);

        migrationBuilder.AddColumn<long>(
            name: "AuthTime",
            table: "AuthorizationCodes",
            type: "INTEGER",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "AcrValue",
            table: "AuthorizationCodes",
            type: "TEXT",
            maxLength: 256,
            nullable: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "DPopJkt",
            table: "RefreshTokens");

        migrationBuilder.DropColumn(
            name: "AuthTime",
            table: "AuthorizationCodes");

        migrationBuilder.DropColumn(
            name: "AcrValue",
            table: "AuthorizationCodes");

        migrationBuilder.AlterColumn<string>(
            name: "CodeChallengeMethod",
            table: "ParEntries",
            type: "TEXT",
            maxLength: 10,
            nullable: false,
            defaultValue: "",
            oldClrType: typeof(string),
            oldType: "TEXT",
            oldMaxLength: 10,
            oldNullable: true);

        migrationBuilder.AlterColumn<string>(
            name: "CodeChallenge",
            table: "ParEntries",
            type: "TEXT",
            maxLength: 256,
            nullable: false,
            defaultValue: "",
            oldClrType: typeof(string),
            oldType: "TEXT",
            oldMaxLength: 256,
            oldNullable: true);

        migrationBuilder.AlterColumn<string>(
            name: "CodeChallenge",
            table: "AuthorizationCodes",
            type: "TEXT",
            maxLength: 256,
            nullable: false,
            defaultValue: "",
            oldClrType: typeof(string),
            oldType: "TEXT",
            oldMaxLength: 256,
            oldNullable: true);
    }
}
