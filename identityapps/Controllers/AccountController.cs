using identityapps.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace identityapps.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _userRole;
        private readonly SignInManager<IdentityUser> _signinManager;
        
          
        public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> userRole,SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signinManager = signInManager;
            _userRole = userRole;
        }
        public IActionResult Index()
        {
            return View();
        }      
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnurl)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model,string returnurl)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {                
                var result = await _signinManager.PasswordSignInAsync(model.Email,model.Password,model.RememberMe,lockoutOnFailure:true);
                if (result.Succeeded)
                {                 
                    return LocalRedirect(returnurl);
                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty,"Username or Password is wrong.");
                }
            }
            return View(model);
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Register(string returnurl)
        {
            if(!await _userRole.RoleExistsAsync("Admin"))
            {
                await _userRole.CreateAsync(new IdentityRole("admin"));
                await _userRole.CreateAsync(new IdentityRole("user"));
            }
            List<SelectListItem> roleList = new List<SelectListItem>();
            roleList.Add(new SelectListItem()
            {
                Value = "Admin",
                Text = "Admin"
            });
            roleList.Add(new SelectListItem()
            {
                Value = "User",
                Text = "User"
            });

            ViewData["ReturnUrl"] = returnurl;
            var registermodel = new RegisterViewModel()
            {
                RoleList = roleList
            };
            return View(registermodel);
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnurl)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser {UserName=model.Email,Email=model.Email,Name=model.Name };
                var result = await _userManager.CreateAsync(user,model.Password);
                if (result.Succeeded)
                {
                    if(model.RoleSelected != null && model.RoleSelected.Length > 0 && model.RoleSelected == "Admin")
                    {
                        await _userManager.AddToRoleAsync(user, "Admin");
                    }
                    else
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                    }
                   await _signinManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl); 
                }
                AddErrors(result);
            }
            List<SelectListItem> roleList = new List<SelectListItem>();
            roleList.Add(new SelectListItem()
            {
                Value = "Admin",
                Text = "Admin"
            });
            roleList.Add(new SelectListItem()
            {
                Value = "User",
                Text = "User"
            });
            model.RoleList = roleList;
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signinManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index),"Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {            
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLogin(string provider,string returnurl)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account",new { ReturnUrl = returnurl});
            var properties = _signinManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnurl, string remoteError=null)
        {
            if(remoteError != null)
            {
                ModelState.AddModelError(string.Empty, "Error occured");
            }
            var info = await _signinManager.GetExternalLoginInfoAsync();
            if(info == null)
            {
                return RedirectToAction(nameof(Login));
            }
            var result = await _signinManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (result.Succeeded)
            {
                
                await _signinManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnurl);
            }
            else
            {
                ViewData["ReturnUrl"] = returnurl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                return View("ExternalLoginConfirmation",new ExternalLoginConfirmationViewModel { Email=email});

            }            
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ForgotPassword(ForgotPasswordViewModel model)
        {           
            return View(model);
        }
        private void AddErrors (IdentityResult result)
        {
            foreach (var error  in result.Errors)
            {
                ModelState.AddModelError(string.Empty,error.Description);
            }
        }
    }
}
