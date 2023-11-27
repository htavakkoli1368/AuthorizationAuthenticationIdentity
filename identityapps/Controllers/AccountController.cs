using identityapps.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Threading.Tasks;

namespace identityapps.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signinManager;
        
          
        public AccountController(UserManager<IdentityUser> userManager,SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signinManager = signInManager;
        }
        public IActionResult Index()
        {
            return View();
        }      
        [HttpGet]
        public IActionResult Login(string returnurl)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }
        [HttpPost]
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
        public IActionResult Register(string returnurl)
        {
            ViewData["ReturnUrl"] = returnurl;
            var registermodel = new RegisterViewModel();
            return View(registermodel);
        }
        [HttpPost]
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
                   await _signinManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl); 
                }
                AddErrors(result);
            }            
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
        public IActionResult ForgotPassword()
        {            
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider,string returnurl)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account",new { ReturnUrl = returnurl});
            var properties = _signinManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }
        [HttpGet]        
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
