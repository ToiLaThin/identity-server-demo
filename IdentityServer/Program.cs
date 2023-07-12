using IdentityServer;
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
    cookieConfig.Cookie.Name = "Identity.Cookie";
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

builder.Services.AddControllersWithViews();

var app = builder.Build();
app.UseIdentityServer();
app.MapDefaultControllerRoute();
app.Run();

