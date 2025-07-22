using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using PhageVirusDashboard.Models;
using PhageVirusDashboard.Services;

namespace PhageVirusDashboard.Controllers
{
    public class AuthController : Controller
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // Login page
        public IActionResult Login()
        {
            return View();
        }

        // Login action
        [HttpPost]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return View(request);
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.LoginAsync(request, ipAddress, userAgent);

            if (response.Success)
            {
                // Store user info in session
                HttpContext.Session.SetString("AuthToken", response.Token!);
                HttpContext.Session.SetString("UserEmail", response.User!.Email);
                HttpContext.Session.SetString("UserName", response.User.FullName);

                return RedirectToAction("Index", "Dashboard");
            }

            ModelState.AddModelError("", response.Message);
            return View(request);
        }

        // Logout action
        public async Task<IActionResult> Logout()
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (!string.IsNullOrEmpty(token))
            {
                await _authService.LogoutAsync(token);
            }

            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        // User Management
        [HttpGet]
        public async Task<IActionResult> Users(int page = 1)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.ViewUsers))
            {
                return RedirectToAction("Login");
            }

            var response = await _authService.GetUsersAsync(page, 20);
            return View(response.Data);
        }

        [HttpGet]
        public async Task<IActionResult> CreateUser()
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.CreateUsers))
            {
                return RedirectToAction("Login");
            }

            return View(new CreateUserRequest());
        }

        [HttpPost]
        public async Task<IActionResult> CreateUser(CreateUserRequest request)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.CreateUsers))
            {
                return RedirectToAction("Login");
            }

            if (!ModelState.IsValid)
            {
                return View(request);
            }

            var response = await _authService.CreateUserAsync(request);

            if (response.Success)
            {
                TempData["SuccessMessage"] = "User created successfully";
                return RedirectToAction("Users");
            }

            ModelState.AddModelError("", response.Message);
            return View(request);
        }

        [HttpGet]
        public async Task<IActionResult> EditUser(string id)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.UpdateUsers))
            {
                return RedirectToAction("Login");
            }

            // Get user details and roles for editing
            var usersResponse = await _authService.GetUsersAsync(1, 1000);
            var user = usersResponse.Data?.Users.Find(u => u.Id == id);

            if (user == null)
            {
                return NotFound();
            }

            var updateRequest = new UpdateUserRequest
            {
                FullName = user.FullName,
                Department = user.Department,
                JobTitle = user.JobTitle,
                PhoneNumber = user.PhoneNumber,
                IsActive = user.IsActive,
                RoleIds = user.RoleIds,
                ProfilePictureUrl = user.ProfilePictureUrl
            };

            ViewBag.User = user;
            return View(updateRequest);
        }

        [HttpPost]
        public async Task<IActionResult> EditUser(string id, UpdateUserRequest request)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.UpdateUsers))
            {
                return RedirectToAction("Login");
            }

            if (!ModelState.IsValid)
            {
                return View(request);
            }

            var response = await _authService.UpdateUserAsync(id, request);

            if (response.Success)
            {
                TempData["SuccessMessage"] = "User updated successfully";
                return RedirectToAction("Users");
            }

            ModelState.AddModelError("", response.Message);
            return View(request);
        }

        [HttpPost]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.DeleteUsers))
            {
                return Json(new { success = false, message = "Unauthorized" });
            }

            var response = await _authService.DeleteUserAsync(id);

            return Json(new { success = response.Success, message = response.Message });
        }

        [HttpPost]
        public async Task<IActionResult> LockUser(string id)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.UpdateUsers))
            {
                return Json(new { success = false, message = "Unauthorized" });
            }

            var response = await _authService.LockUserAsync(id);

            return Json(new { success = response.Success, message = response.Message });
        }

        [HttpPost]
        public async Task<IActionResult> UnlockUser(string id)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.UpdateUsers))
            {
                return Json(new { success = false, message = "Unauthorized" });
            }

            var response = await _authService.UnlockUserAsync(id);

            return Json(new { success = response.Success, message = response.Message });
        }

        // Role Management
        [HttpGet]
        public async Task<IActionResult> Roles(int page = 1)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.ViewRoles))
            {
                return RedirectToAction("Login");
            }

            var response = await _authService.GetRolesAsync(page, 20);
            return View(response.Data);
        }

        [HttpGet]
        public async Task<IActionResult> CreateRole()
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.CreateRoles))
            {
                return RedirectToAction("Login");
            }

            return View(new CreateRoleRequest());
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole(CreateRoleRequest request)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.CreateRoles))
            {
                return RedirectToAction("Login");
            }

            if (!ModelState.IsValid)
            {
                return View(request);
            }

            var response = await _authService.CreateRoleAsync(request);

            if (response.Success)
            {
                TempData["SuccessMessage"] = "Role created successfully";
                return RedirectToAction("Roles");
            }

            ModelState.AddModelError("", response.Message);
            return View(request);
        }

        [HttpGet]
        public async Task<IActionResult> EditRole(string id)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.UpdateRoles))
            {
                return RedirectToAction("Login");
            }

            var rolesResponse = await _authService.GetRolesAsync(1, 1000);
            var role = rolesResponse.Data?.Roles.Find(r => r.Id == id);

            if (role == null)
            {
                return NotFound();
            }

            var updateRequest = new UpdateRoleRequest
            {
                Description = role.Description,
                PermissionIds = role.PermissionIds
            };

            ViewBag.Role = role;
            return View(updateRequest);
        }

        [HttpPost]
        public async Task<IActionResult> EditRole(string id, UpdateRoleRequest request)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.UpdateRoles))
            {
                return RedirectToAction("Login");
            }

            if (!ModelState.IsValid)
            {
                return View(request);
            }

            var response = await _authService.UpdateRoleAsync(id, request);

            if (response.Success)
            {
                TempData["SuccessMessage"] = "Role updated successfully";
                return RedirectToAction("Roles");
            }

            ModelState.AddModelError("", response.Message);
            return View(request);
        }

        [HttpPost]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.DeleteRoles))
            {
                return Json(new { success = false, message = "Unauthorized" });
            }

            var response = await _authService.DeleteRoleAsync(id);

            return Json(new { success = response.Success, message = response.Message });
        }

        // Profile Management
        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token))
            {
                return RedirectToAction("Login");
            }

            var user = await _authService.GetCurrentUserAsync(token);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            return View(user);
        }

        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token))
            {
                return RedirectToAction("Login");
            }

            var user = await _authService.GetCurrentUserAsync(token);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            return View(new ChangePasswordRequest());
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordRequest request)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token))
            {
                return RedirectToAction("Login");
            }

            var user = await _authService.GetCurrentUserAsync(token);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            if (!ModelState.IsValid)
            {
                return View(request);
            }

            var response = await _authService.ChangePasswordAsync(user.Id, request);

            if (response.Success)
            {
                TempData["SuccessMessage"] = "Password changed successfully";
                return RedirectToAction("Profile");
            }

            ModelState.AddModelError("", response.Message);
            return View(request);
        }

        // API Endpoints for AJAX calls
        [HttpGet]
        public async Task<IActionResult> GetCurrentUser()
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token))
            {
                return Json(new { success = false, message = "Not authenticated" });
            }

            var user = await _authService.GetCurrentUserAsync(token);
            if (user == null)
            {
                return Json(new { success = false, message = "Invalid session" });
            }

            return Json(new { success = true, data = user });
        }

        [HttpPost]
        public async Task<IActionResult> AssignRole(string userId, string roleId)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.ManageUserRoles))
            {
                return Json(new { success = false, message = "Unauthorized" });
            }

            var response = await _authService.AssignRoleToUserAsync(userId, roleId);

            return Json(new { success = response.Success, message = response.Message });
        }

        [HttpPost]
        public async Task<IActionResult> RemoveRole(string userId, string roleId)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token) || !await _authService.HasPermissionAsync(token, DashboardPermissions.ManageUserRoles))
            {
                return Json(new { success = false, message = "Unauthorized" });
            }

            var response = await _authService.RemoveRoleFromUserAsync(userId, roleId);

            return Json(new { success = response.Success, message = response.Message });
        }

        [HttpGet]
        public async Task<IActionResult> CheckPermission(string permission)
        {
            var token = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(token))
            {
                return Json(new { success = false, hasPermission = false });
            }

            var hasPermission = await _authService.HasPermissionAsync(token, permission);

            return Json(new { success = true, hasPermission });
        }
    }
} 