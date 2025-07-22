using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using PhageVirusDashboard.Services;

namespace PhageVirusDashboard.Filters
{
    public class RequireAuthAttribute : ActionFilterAttribute
    {
        public string? Permission { get; set; }
        public string? Role { get; set; }

        public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var authService = context.HttpContext.RequestServices.GetService<IAuthService>();
            if (authService == null)
            {
                context.Result = new RedirectToActionResult("Login", "Auth", null);
                return;
            }

            var token = context.HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token))
            {
                context.Result = new RedirectToActionResult("Login", "Auth", null);
                return;
            }

            // Validate token
            if (!await authService.ValidateTokenAsync(token))
            {
                context.HttpContext.Session.Clear();
                context.Result = new RedirectToActionResult("Login", "Auth", null);
                return;
            }

            // Check permission if specified
            if (!string.IsNullOrEmpty(Permission))
            {
                if (!await authService.HasPermissionAsync(token, Permission))
                {
                    context.Result = new ForbidResult();
                    return;
                }
            }

            // Check role if specified
            if (!string.IsNullOrEmpty(Role))
            {
                if (!await authService.HasRoleAsync(token, Role))
                {
                    context.Result = new ForbidResult();
                    return;
                }
            }

            await next();
        }
    }

    public class RequirePermissionAttribute : RequireAuthAttribute
    {
        public RequirePermissionAttribute(string permission)
        {
            Permission = permission;
        }
    }

    public class RequireRoleAttribute : RequireAuthAttribute
    {
        public RequireRoleAttribute(string role)
        {
            Role = role;
        }
    }
} 