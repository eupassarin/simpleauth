using System.ComponentModel.DataAnnotations;

namespace SimpleAuth.EntityFramework.Entities;

/// <summary>EF Core entity for persisted server settings (key-value pairs).</summary>
internal sealed class ServerSettingsEntity
{
    /// <summary>Setting key (e.g., "RateLimit.TokenPermitLimit").</summary>
    [Key]
    [MaxLength(256)]
    public required string Key { get; set; }

    /// <summary>Setting value (serialized as string).</summary>
    [MaxLength(4000)]
    public required string Value { get; set; }

    /// <summary>When this setting was last updated.</summary>
    public required DateTime UpdatedAt { get; set; }
}
