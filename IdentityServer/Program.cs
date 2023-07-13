using IdentityServer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);

//config asp.net core identity for storing user infomation
string connString = builder.Configuration.GetConnectionString("MyConnStr");
builder.Services.AddDbContext<IdentityDbContext>(identityDbConfig =>
{
    identityDbConfig.UseSqlServer(connString, sqlServerConfig =>
    {
        sqlServerConfig.MigrationsAssembly(Assembly.GetExecutingAssembly().GetName().Name);
    });
});
builder.Services.AddIdentity<IdentityUser, IdentityRole>(identityConfig =>
{
    identityConfig.Password.RequiredLength = 4;
    identityConfig.Password.RequireDigit = false;
    identityConfig.Password.RequireUppercase = false;
    identityConfig.Password.RequireNonAlphanumeric = false;
})
    .AddEntityFrameworkStores<IdentityDbContext>()
    .AddUserManager<UserManager<IdentityUser>>()
    .AddSignInManager<SignInManager<IdentityUser>>();
//configure cookie to store identity server session
builder.Services.ConfigureApplicationCookie(cookieConfig =>
{
    cookieConfig.Cookie.Name = "Identity.Cookie"; //=> cookie represent authenticated with idenityserver via google diff from Identity.External
    cookieConfig.LoginPath = "/Auth/Login";
});


builder.Services.AddIdentityServer(identityServerOption =>
{
    identityServerOption.UserInteraction.LoginUrl = "/Auth/Login";
})
    .AddAspNetIdentity<IdentityUser>()
    .AddInMemoryClients(IdentityServerConfiguration.GetClients())
    .AddInMemoryApiResources(IdentityServerConfiguration.GetApis())
    .AddInMemoryIdentityResources(IdentityServerConfiguration.GetIdentities())
    .AddInMemoryApiScopes(IdentityServerConfiguration.GetScopes())
    .AddDeveloperSigningCredential();

builder.Services.AddAuthentication().AddGoogle("Google", googleOption =>
 {
     googleOption.ClientId = builder.Configuration.GetSection("Authentication:Google:ClientId").Value;
     googleOption.ClientSecret = builder.Configuration.GetSection("Authentication:Google:ClientSecret").Value;
     googleOption.SignInScheme = IdentityConstants.ExternalScheme; //Identity.External will be default => cookie represent authenticated with google
     //googleOption.SaveTokens = true; //để lấy access token trong callback uri
 });

builder.Services.AddControllersWithViews();

var app = builder.Build();
app.UseIdentityServer();
app.MapDefaultControllerRoute();
app.Run();

