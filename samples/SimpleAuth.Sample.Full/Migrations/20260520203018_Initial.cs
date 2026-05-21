using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SimpleAuth.Sample.Full.Migrations;

/// <inheritdoc />
public partial class Initial : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AuthorizationCodes",
            columns: table => new
            {
                Handle = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                ClientId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                SubjectId = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                RedirectUri = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                CodeChallenge = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                GrantedScopes = table.Column<string>(type: "TEXT", nullable: false),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                Nonce = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                SessionId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                IsConsumed = table.Column<bool>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AuthorizationCodes", x => x.Handle);
            });

        migrationBuilder.CreateTable(
            name: "Clients",
            columns: table => new
            {
                ClientId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                ClientName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                AllowedGrantTypes = table.Column<string>(type: "TEXT", nullable: false),
                RedirectUris = table.Column<string>(type: "TEXT", nullable: false),
                PostLogoutRedirectUris = table.Column<string>(type: "TEXT", nullable: false),
                AllowedCorsOrigins = table.Column<string>(type: "TEXT", nullable: false),
                AllowedScopes = table.Column<string>(type: "TEXT", nullable: false),
                ClientCredentials = table.Column<string>(type: "TEXT", nullable: false),
                Claims = table.Column<string>(type: "TEXT", nullable: false),
                TokenEndpointAuthMethod = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                RequireClientSecret = table.Column<bool>(type: "INTEGER", nullable: false),
                JwksJson = table.Column<string>(type: "TEXT", nullable: true),
                JwksUri = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                RequirePkce = table.Column<bool>(type: "INTEGER", nullable: false),
                AllowOfflineAccess = table.Column<bool>(type: "INTEGER", nullable: false),
                AccessTokenLifetimeSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                AuthorizationCodeLifetimeSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                RefreshTokenLifetimeSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                IdentityTokenLifetimeSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                RefreshTokenUsage = table.Column<int>(type: "INTEGER", nullable: false),
                RefreshTokenExpiration = table.Column<int>(type: "INTEGER", nullable: false),
                AccessTokenType = table.Column<int>(type: "INTEGER", nullable: false),
                RequireConsent = table.Column<bool>(type: "INTEGER", nullable: false),
                AllowRememberConsent = table.Column<bool>(type: "INTEGER", nullable: false),
                AlwaysIncludeUserClaimsInIdToken = table.Column<bool>(type: "INTEGER", nullable: false),
                SubjectType = table.Column<int>(type: "INTEGER", nullable: false),
                PairwiseSectorIdentifierUri = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Clients", x => x.ClientId);
            });

        migrationBuilder.CreateTable(
            name: "IdentityScopes",
            columns: table => new
            {
                Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                DisplayName = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                ClaimTypes = table.Column<string>(type: "TEXT", nullable: false),
                Required = table.Column<bool>(type: "INTEGER", nullable: false),
                Emphasize = table.Column<bool>(type: "INTEGER", nullable: false),
                ShowInDiscoveryDocument = table.Column<bool>(type: "INTEGER", nullable: false),
                Enabled = table.Column<bool>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_IdentityScopes", x => x.Name);
            });

        migrationBuilder.CreateTable(
            name: "IssuedTokens",
            columns: table => new
            {
                Handle = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                ClientId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                SubjectId = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                GrantedScopes = table.Column<string>(type: "TEXT", nullable: false),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                IsRevoked = table.Column<bool>(type: "INTEGER", nullable: false),
                RefreshTokenHandle = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                JktThumbprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_IssuedTokens", x => x.Handle);
            });

        migrationBuilder.CreateTable(
            name: "JtiRecords",
            columns: table => new
            {
                Jti = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_JtiRecords", x => x.Jti);
            });

        migrationBuilder.CreateTable(
            name: "ParEntries",
            columns: table => new
            {
                RequestUri = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                ClientId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                RedirectUri = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                Scope = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                CodeChallenge = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                CodeChallengeMethod = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                ResponseType = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                State = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                Nonce = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ParEntries", x => x.RequestUri);
            });

        migrationBuilder.CreateTable(
            name: "ProtectedResources",
            columns: table => new
            {
                Name = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                DisplayName = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                Scopes = table.Column<string>(type: "TEXT", nullable: false),
                Enabled = table.Column<bool>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ProtectedResources", x => x.Name);
            });

        migrationBuilder.CreateTable(
            name: "RefreshTokens",
            columns: table => new
            {
                Handle = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                ClientId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                SubjectId = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                GrantedScopes = table.Column<string>(type: "TEXT", nullable: false),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                SlidingExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                SessionId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                IsRevoked = table.Column<bool>(type: "INTEGER", nullable: false),
                Generation = table.Column<int>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_RefreshTokens", x => x.Handle);
            });

        migrationBuilder.CreateTable(
            name: "Scopes",
            columns: table => new
            {
                Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                DisplayName = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                ShowInDiscoveryDocument = table.Column<bool>(type: "INTEGER", nullable: false),
                Required = table.Column<bool>(type: "INTEGER", nullable: false),
                Emphasize = table.Column<bool>(type: "INTEGER", nullable: false),
                Enabled = table.Column<bool>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Scopes", x => x.Name);
            });

        migrationBuilder.CreateTable(
            name: "SigningKeys",
            columns: table => new
            {
                KeyId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                Algorithm = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                PrivateKeyPem = table.Column<string>(type: "TEXT", maxLength: 10000, nullable: false),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                RetireAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                RemoveAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                IsPrimary = table.Column<bool>(type: "INTEGER", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_SigningKeys", x => x.KeyId);
            });

        migrationBuilder.CreateTable(
            name: "UserConsents",
            columns: table => new
            {
                SubjectId = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                ClientId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                GrantedScopes = table.Column<string>(type: "TEXT", nullable: false),
                CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UserConsents", x => new { x.SubjectId, x.ClientId });
            });

        migrationBuilder.CreateIndex(
            name: "IX_AuthorizationCodes_ExpiresAt",
            table: "AuthorizationCodes",
            column: "ExpiresAt");

        migrationBuilder.CreateIndex(
            name: "IX_AuthorizationCodes_Handle",
            table: "AuthorizationCodes",
            column: "Handle",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_AuthorizationCodes_SubjectId_ClientId",
            table: "AuthorizationCodes",
            columns: ["SubjectId", "ClientId"]);

        migrationBuilder.CreateIndex(
            name: "IX_Clients_ClientId",
            table: "Clients",
            column: "ClientId",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_IssuedTokens_ExpiresAt",
            table: "IssuedTokens",
            column: "ExpiresAt");

        migrationBuilder.CreateIndex(
            name: "IX_IssuedTokens_Handle",
            table: "IssuedTokens",
            column: "Handle",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_IssuedTokens_RefreshTokenHandle",
            table: "IssuedTokens",
            column: "RefreshTokenHandle");

        migrationBuilder.CreateIndex(
            name: "IX_IssuedTokens_SubjectId_ClientId",
            table: "IssuedTokens",
            columns: ["SubjectId", "ClientId"]);

        migrationBuilder.CreateIndex(
            name: "IX_JtiRecords_ExpiresAt",
            table: "JtiRecords",
            column: "ExpiresAt");

        migrationBuilder.CreateIndex(
            name: "IX_ParEntries_ExpiresAt",
            table: "ParEntries",
            column: "ExpiresAt");

        migrationBuilder.CreateIndex(
            name: "IX_RefreshTokens_ExpiresAt",
            table: "RefreshTokens",
            column: "ExpiresAt");

        migrationBuilder.CreateIndex(
            name: "IX_RefreshTokens_Handle",
            table: "RefreshTokens",
            column: "Handle",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_RefreshTokens_SubjectId_ClientId",
            table: "RefreshTokens",
            columns: ["SubjectId", "ClientId"]);

        migrationBuilder.CreateIndex(
            name: "IX_SigningKeys_IsPrimary",
            table: "SigningKeys",
            column: "IsPrimary");

        migrationBuilder.CreateIndex(
            name: "IX_SigningKeys_RemoveAt",
            table: "SigningKeys",
            column: "RemoveAt");

        migrationBuilder.CreateIndex(
            name: "IX_UserConsents_SubjectId_ClientId",
            table: "UserConsents",
            columns: ["SubjectId", "ClientId"],
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "AuthorizationCodes");

        migrationBuilder.DropTable(
            name: "Clients");

        migrationBuilder.DropTable(
            name: "IdentityScopes");

        migrationBuilder.DropTable(
            name: "IssuedTokens");

        migrationBuilder.DropTable(
            name: "JtiRecords");

        migrationBuilder.DropTable(
            name: "ParEntries");

        migrationBuilder.DropTable(
            name: "ProtectedResources");

        migrationBuilder.DropTable(
            name: "RefreshTokens");

        migrationBuilder.DropTable(
            name: "Scopes");

        migrationBuilder.DropTable(
            name: "SigningKeys");

        migrationBuilder.DropTable(
            name: "UserConsents");
    }
}
