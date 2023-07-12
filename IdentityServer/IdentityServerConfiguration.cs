using IdentityModel;
using IdentityServer4.Models;
using System.Linq.Expressions;

namespace IdentityServer
{
    public static class IdentityServerConfiguration
    {
        public static IEnumerable<IdentityResource> GetIdentities() => new List<IdentityResource>()
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile()
        };

        public static IEnumerable<ApiResource> GetApis() => new List<ApiResource>
        {
            new ApiResource("ApiOne"),
        };

        public static IEnumerable<Client> GetClients() => new List<Client>
        {
            new Client()
            {
                ClientId = "client_id",
                ClientSecrets = { new Secret("client_secret".ToSha256()) },
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                AllowedScopes = { "ApiOne" },

                RequireConsent = false,
                RedirectUris = { "https://localhost:7081/signin-oidc" }

                
                
            }
        };
    }
}
