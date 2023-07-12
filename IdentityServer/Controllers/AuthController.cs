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
        public IActionResult Login(string returnUrl = "https://localhost:7134/Auth/Register")
        {
            return View(new LoginViewModel { ReturnUrl = returnUrl });
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

    }
}
