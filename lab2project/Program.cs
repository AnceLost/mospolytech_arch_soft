using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// 1. Настройка базы данных в памяти
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseInMemoryDatabase("IncidentsDb"));

// 2. Настройка аутентификации
var jwtKey = "super-secret-key-that-should-be-at-least-32-bytes-long!";
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "IncidentApp",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IIncidentService, IncidentService>();

// Включить CORS (разрешить запросы с любого источника — только для разработки!)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

app.UseCors("AllowAll");
app.UseDefaultFiles();
app.UseStaticFiles();

// Инициализация тестовых данных
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Users.Add(new User { Id = 1, Email = "admin@test.com", FullName = "Администратор", 
        PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456"), Role = UserRole.Admin });
    db.Users.Add(new User { Id = 2, Email = "user@test.com", FullName = "Пользователь", 
        PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456"), Role = UserRole.User });
    db.IncidentCategories.Add(new IncidentCategory { Id = 1, Name = "Общая" });
    db.SaveChanges();
}

app.UseAuthentication();
app.UseAuthorization();

// === API Endpoints ===
app.MapPost("/api/auth/login", async (LoginRequest req, IAuthService auth) =>
{
    var token = await auth.LoginAsync(req.Email, req.Password);
    return token is null ? Results.Unauthorized() : Results.Ok(new { token });
});

app.MapPost("/api/incidents", [Authorize] async (CreateIncidentRequest req, IIncidentService service, ClaimsPrincipal user) =>
{
    var userId = int.Parse(user.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    var incident = await service.CreateAsync(req, userId);
    return Results.Created($"/api/incidents/{incident.Id}", incident);
});

app.MapGet("/api/incidents", [Authorize] async (IIncidentService service, ClaimsPrincipal user) =>
{
    var userId = int.Parse(user.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    var userRole = Enum.Parse<UserRole>(user.FindFirst(ClaimTypes.Role)!.Value);
    var incidents = await service.GetListAsync(userId, userRole);
    return Results.Ok(incidents);
});

app.MapGet("/api/incidents/{id}", [Authorize] async (int id, IIncidentService service, ClaimsPrincipal user) =>
{
    var userId = int.Parse(user.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    var userRole = Enum.Parse<UserRole>(user.FindFirst(ClaimTypes.Role)!.Value);
    var incident = await service.GetByIdAsync(id, userId, userRole);
    return incident is null ? Results.NotFound() : Results.Ok(incident);
});

app.MapPut("/api/incidents/{id}", [Authorize] async (int id, UpdateIncidentRequest req, IIncidentService service, ClaimsPrincipal user) =>
{
    var userId = int.Parse(user.FindFirst(ClaimTypes.NameIdentifier)!.Value);
    var userRole = Enum.Parse<UserRole>(user.FindFirst(ClaimTypes.Role)!.Value);
    try
    {
        var updated = await service.UpdateAsync(id, req, userId, userRole);
        return Results.Ok(updated);
    }
    catch (UnauthorizedAccessException) { return Results.Forbid(); }
});

app.MapDelete("/api/incidents/{id}", [Authorize(Roles = "Admin")] async (int id, IIncidentService service) =>
{
    await service.DeleteAsync(id);
    return Results.NoContent();
});

app.Run();

// ========== Модели ==========
public record LoginRequest(string Email, string Password);
public record CreateIncidentRequest(string Title, string Description, int CategoryId);
public record UpdateIncidentRequest(string Title, string Description, IncidentStatus Status);
public record IncidentResponse(int Id, string Title, string Description, IncidentStatus Status, DateTime CreatedAt);

public enum UserRole { User, Admin }
public enum IncidentStatus { New, InProgress, Resolved, Closed }

public class User
{
    public int Id { get; set; }
    public string FullName { get; set; } = "";
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public UserRole Role { get; set; }
}

public class IncidentCategory
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
}

public class Incident
{
    public int Id { get; set; }
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public IncidentStatus Status { get; set; } = IncidentStatus.New;
    public int CategoryId { get; set; }
    public IncidentCategory Category { get; set; } = null!;
    public int CreatedById { get; set; }
    public User CreatedBy { get; set; } = null!;
}

// ========== DbContext ==========
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<User> Users => Set<User>();
    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<IncidentCategory> IncidentCategories => Set<IncidentCategory>();
}

// ========== Сервисы ==========
public interface IAuthService
{
    Task<string?> LoginAsync(string email, string password);
}

public class AuthService : IAuthService
{
    private readonly AppDbContext _db;
    public AuthService(AppDbContext db) => _db = db;

    public async Task<string?> LoginAsync(string email, string password)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
        if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            return null;

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Role, user.Role.ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("super-secret-key-that-should-be-at-least-32-bytes-long!"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: "IncidentApp",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(24),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

public interface IIncidentService
{
    Task<IncidentResponse> CreateAsync(CreateIncidentRequest req, int userId);
    Task<List<IncidentResponse>> GetListAsync(int userId, UserRole role);
    Task<IncidentResponse?> GetByIdAsync(int id, int userId, UserRole role);
    Task<IncidentResponse> UpdateAsync(int id, UpdateIncidentRequest req, int userId, UserRole role);
    Task DeleteAsync(int id);
}

public class IncidentService : IIncidentService
{
    private readonly AppDbContext _db;
    public IncidentService(AppDbContext db) => _db = db;

    public async Task<IncidentResponse> CreateAsync(CreateIncidentRequest req, int userId)
    {
        var incident = new Incident
        {
            Title = req.Title,
            Description = req.Description,
            CategoryId = req.CategoryId,
            CreatedById = userId
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        return new IncidentResponse(incident.Id, incident.Title, incident.Description, incident.Status, incident.CreatedAt);
    }

    public async Task<List<IncidentResponse>> GetListAsync(int userId, UserRole role)
    {
        var query = _db.Incidents.AsQueryable();
        if (role != UserRole.Admin)
            query = query.Where(i => i.CreatedById == userId);
        
        return await query.Select(i => new IncidentResponse(i.Id, i.Title, i.Description, i.Status, i.CreatedAt)).ToListAsync();
    }

    public async Task<IncidentResponse?> GetByIdAsync(int id, int userId, UserRole role)
    {
        var incident = await _db.Incidents.FindAsync(id);
        if (incident == null) return null;
        if (role != UserRole.Admin && incident.CreatedById != userId) return null;
        
        return new IncidentResponse(incident.Id, incident.Title, incident.Description, incident.Status, incident.CreatedAt);
    }

    public async Task<IncidentResponse> UpdateAsync(int id, UpdateIncidentRequest req, int userId, UserRole role)
    {
        var incident = await _db.Incidents.FindAsync(id);
        if (incident == null) throw new InvalidOperationException("Incident not found");
        if (role != UserRole.Admin && incident.CreatedById != userId) throw new UnauthorizedAccessException();

        incident.Title = req.Title;
        incident.Description = req.Description;
        incident.Status = req.Status;
        await _db.SaveChangesAsync();
        return new IncidentResponse(incident.Id, incident.Title, incident.Description, incident.Status, incident.CreatedAt);
    }

    public async Task DeleteAsync(int id)
    {
        var incident = await _db.Incidents.FindAsync(id);
        if (incident != null)
        {
            _db.Incidents.Remove(incident);
            await _db.SaveChangesAsync();
        }
    }
}