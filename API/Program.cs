using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddHttpClient();
builder.Services.AddAuthentication(authConfig =>
{
    authConfig.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    authConfig.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, cookieOption =>
                {
                    //cookieOption.LoginPath = "/login/identityServer4";
                    //cookieOption.AccessDeniedPath = "/unauthorized";
                    //secret api use cookie authentication
                }) 
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, jwtOption =>
                {
                    jwtOption.Authority = "https://localhost:7134";
                    jwtOption.SaveToken = true;                    
                    jwtOption.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuerSigningKey = false,
                        ValidateActor = false,
                        ValidateIssuer = false,
                        ValidateAudience = false,
                    };
                })
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, oidcConfig =>
                {
                    oidcConfig.Authority = "https://localhost:7134";
                    oidcConfig.ClientId = "client_id";
                    oidcConfig.ClientSecret = "client_secret";
                    oidcConfig.SaveTokens = true; //cookie have idtoken and acess token inside of it
                    oidcConfig.ResponseType = "code";
                });


builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
//must be above useAuthorization
app.UseStatusCodePages(async context => {
    var request = context.HttpContext.Request;
    var response = context.HttpContext.Response;

    if (response.StatusCode == (int)HttpStatusCode.Unauthorized)
    // you may also check requests path to do this only for specific methods       
    // && request.Path.Value.StartsWith("/specificPath")

    {
        response.Redirect("/unauthorized");
       }
});
app.UseAuthorization();

app.MapGet("/login/identityServer4", (HttpContext ctx) => {
    return ctx.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties()
    {
        RedirectUri = "/token"
    });
});

app.MapGet("/token", async (HttpContext ctx) =>
{
    var accessToken = await ctx.GetTokenAsync("access_token");
    var idToken = await ctx.GetTokenAsync("id_token");

    var jwtIdToken = new JwtSecurityTokenHandler().ReadJwtToken(idToken);
    var jwtAccessToken = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
    return accessToken.ToString() + "\n" + idToken.ToString();
});

//since multiple authentication scheme is added to the di container, we can specify the one we will use for this api
app.MapGet("/secret", [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] async (HttpContext ctx) =>
{
    return "secret";
});

app.MapGet("/unauthorized", () =>
{
    return $"unauthorized, pls go to https://localhost:7083/login/identityServer4 to login first";
});

app.Run();



