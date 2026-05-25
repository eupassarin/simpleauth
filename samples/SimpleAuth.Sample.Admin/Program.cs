using Microsoft.EntityFrameworkCore;
using SimpleAuth;
using SimpleAuth.Admin;
using SimpleAuth.EntityFramework;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("SimpleAuth")
    ?? "Host=localhost;Database=simpleauth;Username=simpleauth;Password=dev-password";

// Register the DbContext
builder.Services.AddDbContext<SimpleAuthDbContext>(options =>
    options.UseNpgsql(connectionString));

// Configure SimpleAuth OAuth 2.1 + OIDC server
builder.Services.AddSimpleAuth(server =>
{
    server.Issuer = builder.Configuration["SimpleAuth:Issuer"] ?? "http://localhost:5000";
    server.Keys.UseDevelopmentKey();
    server.RateLimit.Enabled = false; // Dev mode
});

// Register EF stores (replaces in-memory stores)
builder.Services.AddSimpleAuthEntityFramework<SimpleAuthDbContext>();

// Register Admin GUI
builder.Services.AddSimpleAuthGui(gui =>
{
    gui.AdminUsername = builder.Configuration["SimpleAuth:AdminUsername"] ?? "admin";
    gui.SetPassword(builder.Configuration["SimpleAuth:AdminPassword"] ?? "admin123");
});

var app = builder.Build();

// Auto-migrate database on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SimpleAuthDbContext>();
    await db.Database.EnsureCreatedAsync();
}

// Middleware (must be before endpoint mappings)
app.UseSimpleAuthGui();

// Endpoints
app.MapSimpleAuth();
app.MapSimpleAuthGui();

app.Run();
