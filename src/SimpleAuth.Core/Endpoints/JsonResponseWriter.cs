using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.AspNetCore.Http;

namespace SimpleAuth.Endpoints;

/// <summary>Writes JSON responses using source-generated metadata.</summary>
internal static class JsonResponseWriter
{
    /// <summary>Serializes a value and writes it to the response body.</summary>
    internal static async Task WriteAsync<T>(HttpContext context, T value, JsonTypeInfo<T> jsonTypeInfo)
    {
        context.Response.ContentType = "application/json; charset=utf-8";
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value, jsonTypeInfo);
        await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
    }
}
