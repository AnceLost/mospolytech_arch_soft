using System;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Xunit;
using lab2project;

namespace lab2project.Tests.Services
{
    public class IncidentServiceTests
    {
        private AppDbContext GetDbContext()
        {
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
            var db = new AppDbContext(options);
            db.IncidentCategories.Add(new IncidentCategory { Id = 1, Name = "Тестовая" });
            db.Users.Add(new User { Id = 1, Email = "admin@test.com", FullName = "Admin", 
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456"), Role = UserRole.Admin });
            db.Users.Add(new User { Id = 2, Email = "exec@test.com", FullName = "Executor", 
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456"), Role = UserRole.Executor });
            db.Users.Add(new User { Id = 3, Email = "user@test.com", FullName = "User", 
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456"), Role = UserRole.User });
            db.SaveChanges();
            return db;
        }

        [Fact]
        public async Task CreateIncident_ValidData_ReturnsIncidentResponse()
        {
            var db = GetDbContext();
            var service = new IncidentService(db);
            var request = new CreateIncidentRequest("Протечка", "Описание", 1);

            var result = await service.CreateAsync(request, userId: 1);

            Assert.NotNull(result);
            Assert.Equal("Протечка", result.Title);
            Assert.Equal(IncidentStatus.New, result.Status);
        }

        [Fact]
        public async Task UpdateStatus_InvalidTransition_ThrowsException()
        {
            var db = GetDbContext();
            var service = new IncidentService(db);
            // создаём заявку со статусом Resolved, из которого нельзя перейти в New
            var incident = new Incident 
            { 
                Title = "t", Description = "d", CategoryId = 1, CreatedById = 1, 
                Status = IncidentStatus.Resolved, AssignedToId = 2 
            };
            db.Incidents.Add(incident);
            db.SaveChanges();

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                service.UpdateStatusAsync(incident.Id, IncidentStatus.New, "комментарий", userId: 1, UserRole.Admin));
        }

        [Fact]
        public async Task UpdateIncident_ByNonOwnerUser_ThrowsUnauthorized()
        {
            var db = GetDbContext();
            var service = new IncidentService(db);
            var incident = new Incident 
            { 
                Title = "t", Description = "d", CategoryId = 1, CreatedById = 1, 
                Status = IncidentStatus.New 
            };
            db.Incidents.Add(incident);
            db.SaveChanges();
            var updateReq = new UpdateIncidentRequest("new", "desc", IncidentStatus.InProgress);

            // Пытаемся обновить заявку от имени пользователя с id=3, который не является автором и не администратор
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                service.UpdateAsync(incident.Id, updateReq, userId: 3, UserRole.User));
        }
    }
}