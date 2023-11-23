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
        public async Task<IActionResult> Register()
        {
            var registermodel = new RegisterViewModel();
            return View(registermodel);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser {UserName=model.Email,Email=model.Email,Name=model.Name };
                var result = await _userManager.CreateAsync(user,model.Password);
                if (result.Succeeded)
                {
                   await _signinManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index","Home");
                }
                AddErrors(result);
            }            
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
