using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using lab2project;
using System;
using System.Linq;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<AppDbContext>));
            if (descriptor != null)
                services.Remove(descriptor);

            services.AddDbContext<AppDbContext>(options =>
                options.UseInMemoryDatabase("TestDb"));

            using var scope = services.BuildServiceProvider().CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Database.EnsureCreated();
            db.Users.Add(new User { Id = 1, Email = "admin@test.com", FullName = "Admin", 
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456"), Role = UserRole.Admin });
            db.Users.Add(new User { Id = 2, Email = "user@test.com", FullName = "User", 
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456"), Role = UserRole.User });
            db.IncidentCategories.Add(new IncidentCategory { Id = 1, Name = "Cat1" });
            db.SaveChanges();
        });
    }
}