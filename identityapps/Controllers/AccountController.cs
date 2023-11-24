using identityapps.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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
        public async Task<IActionResult> Login(string returnurl)
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
                var result = await _signinManager.PasswordSignInAsync(model.Email,model.Password,model.RememberMe,lockoutOnFailure:false);
                if (result.Succeeded)
                {                 
                    return LocalRedirect(returnurl);
                }
                else
                {
                    ModelState.AddModelError(string.Empty,"Username or Password is wrong.");
                }
            }
            return View(model);
        }
        [HttpGet]
        public async Task<IActionResult> Register(string returnurl)
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

        private void AddErrors (IdentityResult result)
        {
            foreach (var error  in result.Errors)
            {
                ModelState.AddModelError(string.Empty,error.Description);
            }
        }
    }
}
