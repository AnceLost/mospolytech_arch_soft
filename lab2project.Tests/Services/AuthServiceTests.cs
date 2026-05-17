using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using lab2project; // пространство имён вашего основного проекта
using Microsoft.EntityFrameworkCore;
using Xunit;

public class AuthServiceTests
{
    [Fact]
    public async Task Login_ValidCredentials_ReturnsToken()
    {
        // Arrange
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase("AuthTest")
            .Options;
        var db = new AppDbContext(options);
        db.Users.Add(new User { Id = 1, Email = "a@b.c", FullName = "Test", PasswordHash = BCrypt.Net.BCrypt.HashPassword("secret"), Role = UserRole.User });
        db.SaveChanges();
        var service = new AuthService(db);

        // Act
        var token = await service.LoginAsync("a@b.c", "secret");

        // Assert
        Assert.NotNull(token);
    }
}