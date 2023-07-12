using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using Microsoft.OpenApi.Writers;
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

        public static IEnumerable<ApiScope> GetScopes() => new List<ApiScope>
        {
            new ApiScope("ApiOne")
        };
        public static IEnumerable<Client> GetClients() => new List<Client>
        {
            new Client()
            {
                ClientId = "client_id",
                ClientSecrets = { new Secret("client_secret".ToSha256()) },
                AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
                AllowedScopes = { "ApiOne", IdentityServerConstants.StandardScopes.OpenId, IdentityServerConstants.StandardScopes.Profile  },

                RequireConsent = false,
                RedirectUris = { "https://localhost:7083/signin-oidc" }

                
                
            }
        };
    }
}
