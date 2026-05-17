using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;
using lab2project;

namespace lab2project.Tests.Integration
{
    public class IntegrationTests : IClassFixture<CustomWebApplicationFactory>
    {
        private readonly HttpClient _client;
        private readonly CustomWebApplicationFactory _factory;

        public IntegrationTests(CustomWebApplicationFactory factory)
        {
            _factory = factory;
            _client = factory.CreateClient();
        }

        private async Task<string> GetAuthToken(string email, string password)
        {
            var response = await _client.PostAsJsonAsync("/api/auth/login", new { email, password });
            response.EnsureSuccessStatusCode();
            var jsonString = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(jsonString);
            return doc.RootElement.GetProperty("token").GetString()!;
        }

        [Fact]
        public async Task GetIncidents_Unauthenticated_Returns401()
        {
            var response = await _client.GetAsync("/api/incidents");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task CreateIncident_AdminRole_Returns201()
        {
            var token = await GetAuthToken("admin@test.com", "123456");
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var requestBody = new { title = "Incident from test", description = "desc", categoryId = 1 };
            var response = await _client.PostAsJsonAsync("/api/incidents", requestBody);

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var incident = await response.Content.ReadFromJsonAsync<IncidentResponse>();
            Assert.NotNull(incident);
            Assert.Equal("Incident from test", incident.Title);
        }

        [Fact]
        public async Task UpdateIncident_ByAdmin_Succeeds()
        {
            var adminToken = await GetAuthToken("admin@test.com", "123456");
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

            // Создаём заявку
            var createResponse = await _client.PostAsJsonAsync("/api/incidents", 
                new CreateIncidentRequest("test", "", 1));
            createResponse.EnsureSuccessStatusCode();
            var created = await createResponse.Content.ReadFromJsonAsync<IncidentResponse>();

            // Обновляем
            var updateRequest = new UpdateIncidentRequest("updated", "updated", IncidentStatus.InProgress);
            var updateResponse = await _client.PutAsJsonAsync($"/api/incidents/{created!.Id}", updateRequest);
            Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);

            var updated = await updateResponse.Content.ReadFromJsonAsync<IncidentResponse>();
            Assert.Equal("updated", updated!.Title);
            Assert.Equal(IncidentStatus.InProgress, updated.Status);
        }
    }

    // Вспомогательный класс для десериализации ответа логина
    public record AuthTokenResponse(string Token);
}