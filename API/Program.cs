using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddHttpClient();
builder.Services.AddAuthentication(authConfig =>
{
    authConfig.DefaultScheme = "cookie";
    authConfig.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
                .AddCookie("cookie")
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, oidcConfig =>
                {
                    oidcConfig.Authority = "https://localhost:7134";
                    oidcConfig.ClientId = "client_id";
                    oidcConfig.ClientSecret = "client_secret";
                    oidcConfig.SaveTokens = true;
                    oidcConfig.ResponseType = "code";
                });


builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();


app.MapGet("/secret", [Authorize] async (HttpContext ctx) =>
{
    var accessToken = await ctx.GetTokenAsync("access_token");
    var idToken = await ctx.GetTokenAsync("id_token");

    var jwtIdToken = new JwtSecurityTokenHandler().ReadJwtToken(idToken);
    var jwtAccessToken = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);

    return "secret";
});

app.Run();



