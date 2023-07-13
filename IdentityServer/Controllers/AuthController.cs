using IdentityServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace IdentityServer.Controllers
{
    public class AuthController : Controller
    { 
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet]
        //from query params
        public async Task<IActionResult> Login(string returnUrl = "https://localhost:7134/Auth/Register")
        {
            var externalProviders = await _signInManager.GetExternalAuthenticationSchemesAsync();
            return View(new LoginViewModel { 
                ReturnUrl = returnUrl,
                ExternalProviders = externalProviders 
            });
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel vm)
        {
            //check if model is valid
            var result = await _signInManager.PasswordSignInAsync(vm.Username, vm.Password, true, true);
            if (result.Succeeded)
            {
                return Redirect(vm.ReturnUrl);
            }
            else
            {

            }
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Register()
        {
            return View();
        }
        
        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel rvm)
        {
            if(rvm.Password == rvm.PasswordConfirmed)
            {
                //phai cos await neu ko se redirect trc khi tao user
                var result = await _userManager.CreateAsync(new IdentityUser(rvm.Username), rvm.Password);
                return View("RegisterSuccess");
            }
            else
            {
                return View();
            }
        }
        public async Task<IActionResult> ExternalLogin(string provider, string returnUrl)
        {
            var redirectUri = Url.Action(nameof(ExteranlLoginCallback), "Auth", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUri);
            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExteranlLoginCallback(string returnUrl)
        {
            //check if we authen with facebook successfully
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                //if not go to login page again
                return RedirectToAction("Login");
            }

            //else sign in get claims and set to ctx.User and may save those claims to db?
            var result = await _signInManager
                .ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false); //ì this succeed will set identity.External cookie

            //if that facebook user is already exist in our db redirect
            if (result.Succeeded)
            {
                return Redirect(returnUrl);
            }

            var ctx = HttpContext;
            //else create that facebook user in db using ExternalRegister
            var username = info.Principal.FindFirst(ClaimTypes.Name).Value; //get info.principle.Name represent the face book username
            //cannot modify the claim so we extract the value then modify the value
            return View("ExternalRegister", new ExternalRegisterViewModel
            {
                Username = username.Replace(" ",""),
                ReturnUrl = returnUrl
            });
        }

        public async Task<IActionResult> ExternalRegister(ExternalRegisterViewModel vm)
        {
            //check again?
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("Login");
            }

            var user = new IdentityUser(vm.Username);
            var result = await _userManager.CreateAsync(user);

            if (!result.Succeeded) {
                return View(vm);
            }

            //if succeed, add login method facebook associated with newly created user
            result = await _userManager.AddLoginAsync(user, info);

            if (!result.Succeeded) {
                return View(vm);
            }

            await _signInManager.SignInAsync(user, false); //will set identity.Cooki and asp.netcore.cookie
            var ctx = HttpContext;
            return Redirect(vm.ReturnUrl);
        }
    }

}
