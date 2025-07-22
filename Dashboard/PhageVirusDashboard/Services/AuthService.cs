using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using PhageVirusDashboard.Models;

namespace PhageVirusDashboard.Services
{
    public interface IAuthService
    {
        Task<LoginResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent);
        Task<bool> LogoutAsync(string token);
        Task<UserInfo?> GetCurrentUserAsync(string token);
        Task<bool> ValidateTokenAsync(string token);
        Task<bool> HasPermissionAsync(string token, string permission);
        Task<bool> HasRoleAsync(string token, string role);
        Task<UserManagementResponse<User>> CreateUserAsync(CreateUserRequest request);
        Task<UserManagementResponse<User>> UpdateUserAsync(string userId, UpdateUserRequest request);
        Task<UserManagementResponse<bool>> DeleteUserAsync(string userId);
        Task<UserManagementResponse<UserListResponse>> GetUsersAsync(int page = 1, int pageSize = 20);
        Task<UserManagementResponse<Role>> CreateRoleAsync(CreateRoleRequest request);
        Task<UserManagementResponse<Role>> UpdateRoleAsync(string roleId, UpdateRoleRequest request);
        Task<UserManagementResponse<bool>> DeleteRoleAsync(string roleId);
        Task<UserManagementResponse<RoleListResponse>> GetRolesAsync(int page = 1, int pageSize = 20);
        Task<UserManagementResponse<bool>> ChangePasswordAsync(string userId, ChangePasswordRequest request);
        Task<UserManagementResponse<bool>> ResetPasswordAsync(ResetPasswordRequest request);
        Task<UserManagementResponse<bool>> LockUserAsync(string userId);
        Task<UserManagementResponse<bool>> UnlockUserAsync(string userId);
        Task<UserManagementResponse<bool>> AssignRoleToUserAsync(string userId, string roleId);
        Task<UserManagementResponse<bool>> RemoveRoleFromUserAsync(string userId, string roleId);
    }

    public class AuthService : IAuthService
    {
        private readonly Dictionary<string, User> _users = new();
        private readonly Dictionary<string, Role> _roles = new();
        private readonly Dictionary<string, Permission> _permissions = new();
        private readonly Dictionary<string, UserSession> _sessions = new();
        private readonly Dictionary<string, string> _userPasswords = new(); // In production, use proper password hashing

        public AuthService()
        {
            InitializeDefaultData();
        }

        public async Task<LoginResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent)
        {
            await Task.Delay(100); // Simulate async operation

            // Find user by email
            var user = _users.Values.FirstOrDefault(u => u.Email.Equals(request.Email, StringComparison.OrdinalIgnoreCase));
            
            if (user == null)
            {
                return new LoginResponse
                {
                    Success = false,
                    Message = "Invalid email or password"
                };
            }

            // Check if user is locked
            if (user.IsLocked)
            {
                if (user.LockedUntil.HasValue && user.LockedUntil.Value > DateTime.UtcNow)
                {
                    return new LoginResponse
                    {
                        Success = false,
                        Message = $"Account is locked until {user.LockedUntil.Value:yyyy-MM-dd HH:mm:ss}"
                    };
                }
                else
                {
                    // Unlock account if lock period has expired
                    user.IsLocked = false;
                    user.FailedLoginAttempts = 0;
                    user.LockedUntil = null;
                }
            }

            // Validate password
            if (!ValidatePassword(user.Id, request.Password))
            {
                user.FailedLoginAttempts++;
                
                // Lock account after 5 failed attempts
                if (user.FailedLoginAttempts >= 5)
                {
                    user.IsLocked = true;
                    user.LockedUntil = DateTime.UtcNow.AddMinutes(30);
                    
                    return new LoginResponse
                    {
                        Success = false,
                        Message = "Account locked due to too many failed login attempts"
                    };
                }

                return new LoginResponse
                {
                    Success = false,
                    Message = "Invalid email or password"
                };
            }

            // Reset failed login attempts on successful login
            user.FailedLoginAttempts = 0;
            user.LastLoginAt = DateTime.UtcNow;

            // Generate session token
            var token = GenerateToken();
            var session = new UserSession
            {
                UserId = user.Id,
                Token = token,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddHours(8), // 8 hour session
                IpAddress = ipAddress,
                UserAgent = userAgent,
                IsActive = true
            };

            _sessions[token] = session;

            // Get user roles and permissions
            var roles = user.RoleIds.Select(roleId => _roles[roleId].Name).ToList();
            var permissions = GetUserPermissions(user.Id);

            return new LoginResponse
            {
                Success = true,
                Message = "Login successful",
                Token = token,
                ExpiresAt = session.ExpiresAt,
                User = new UserInfo
                {
                    Id = user.Id,
                    Email = user.Email,
                    Username = user.Username,
                    FullName = user.FullName,
                    Roles = roles,
                    Permissions = permissions,
                    ProfilePictureUrl = user.ProfilePictureUrl,
                    RequirePasswordChange = user.RequirePasswordChange
                }
            };
        }

        public async Task<bool> LogoutAsync(string token)
        {
            await Task.Delay(50);
            
            if (_sessions.TryGetValue(token, out var session))
            {
                session.IsActive = false;
                return true;
            }
            
            return false;
        }

        public async Task<UserInfo?> GetCurrentUserAsync(string token)
        {
            await Task.Delay(50);

            if (!_sessions.TryGetValue(token, out var session) || !session.IsActive || session.ExpiresAt < DateTime.UtcNow)
            {
                return null;
            }

            if (!_users.TryGetValue(session.UserId, out var user))
            {
                return null;
            }

            var roles = user.RoleIds.Select(roleId => _roles[roleId].Name).ToList();
            var permissions = GetUserPermissions(user.Id);

            return new UserInfo
            {
                Id = user.Id,
                Email = user.Email,
                Username = user.Username,
                FullName = user.FullName,
                Roles = roles,
                Permissions = permissions,
                ProfilePictureUrl = user.ProfilePictureUrl,
                RequirePasswordChange = user.RequirePasswordChange
            };
        }

        public async Task<bool> ValidateTokenAsync(string token)
        {
            await Task.Delay(25);
            
            return _sessions.TryGetValue(token, out var session) && 
                   session.IsActive && 
                   session.ExpiresAt > DateTime.UtcNow;
        }

        public async Task<bool> HasPermissionAsync(string token, string permission)
        {
            var user = await GetCurrentUserAsync(token);
            return user?.Permissions.Contains(permission) ?? false;
        }

        public async Task<bool> HasRoleAsync(string token, string role)
        {
            var user = await GetCurrentUserAsync(token);
            return user?.Roles.Contains(role) ?? false;
        }

        public async Task<UserManagementResponse<User>> CreateUserAsync(CreateUserRequest request)
        {
            await Task.Delay(100);

            // Check if email already exists
            if (_users.Values.Any(u => u.Email.Equals(request.Email, StringComparison.OrdinalIgnoreCase)))
            {
                return new UserManagementResponse<User>
                {
                    Success = false,
                    Message = "User with this email already exists"
                };
            }

            // Check if username already exists
            if (_users.Values.Any(u => u.Username.Equals(request.Username, StringComparison.OrdinalIgnoreCase)))
            {
                return new UserManagementResponse<User>
                {
                    Success = false,
                    Message = "Username already exists"
                };
            }

            var user = new User
            {
                Email = request.Email,
                Username = request.Username,
                FullName = request.FullName,
                Department = request.Department,
                JobTitle = request.JobTitle,
                PhoneNumber = request.PhoneNumber,
                RoleIds = request.RoleIds,
                RequirePasswordChange = request.RequirePasswordChange,
                CreatedAt = DateTime.UtcNow
            };

            _users[user.Id] = user;
            _userPasswords[user.Id] = HashPassword(request.Password);

            return new UserManagementResponse<User>
            {
                Success = true,
                Message = "User created successfully",
                Data = user
            };
        }

        public async Task<UserManagementResponse<User>> UpdateUserAsync(string userId, UpdateUserRequest request)
        {
            await Task.Delay(100);

            if (!_users.TryGetValue(userId, out var user))
            {
                return new UserManagementResponse<User>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            if (request.FullName != null) user.FullName = request.FullName;
            if (request.Department != null) user.Department = request.Department;
            if (request.JobTitle != null) user.JobTitle = request.JobTitle;
            if (request.PhoneNumber != null) user.PhoneNumber = request.PhoneNumber;
            if (request.IsActive.HasValue) user.IsActive = request.IsActive.Value;
            if (request.RoleIds != null) user.RoleIds = request.RoleIds;
            if (request.ProfilePictureUrl != null) user.ProfilePictureUrl = request.ProfilePictureUrl;

            return new UserManagementResponse<User>
            {
                Success = true,
                Message = "User updated successfully",
                Data = user
            };
        }

        public async Task<UserManagementResponse<bool>> DeleteUserAsync(string userId)
        {
            await Task.Delay(100);

            if (!_users.TryGetValue(userId, out var user))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            // Don't allow deletion of system admin
            if (user.RoleIds.Any(roleId => _roles[roleId].Name == DashboardRoles.SuperAdmin))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "Cannot delete super admin user"
                };
            }

            _users.Remove(userId);
            _userPasswords.Remove(userId);

            return new UserManagementResponse<bool>
            {
                Success = true,
                Message = "User deleted successfully",
                Data = true
            };
        }

        public async Task<UserManagementResponse<UserListResponse>> GetUsersAsync(int page = 1, int pageSize = 20)
        {
            await Task.Delay(100);

            var users = _users.Values.Skip((page - 1) * pageSize).Take(pageSize).ToList();
            var totalCount = _users.Count;
            var totalPages = (int)Math.Ceiling((double)totalCount / pageSize);

            return new UserManagementResponse<UserListResponse>
            {
                Success = true,
                Data = new UserListResponse
                {
                    Users = users,
                    TotalCount = totalCount,
                    PageNumber = page,
                    PageSize = pageSize,
                    TotalPages = totalPages
                }
            };
        }

        public async Task<UserManagementResponse<Role>> CreateRoleAsync(CreateRoleRequest request)
        {
            await Task.Delay(100);

            if (_roles.Values.Any(r => r.Name.Equals(request.Name, StringComparison.OrdinalIgnoreCase)))
            {
                return new UserManagementResponse<Role>
                {
                    Success = false,
                    Message = "Role with this name already exists"
                };
            }

            var role = new Role
            {
                Name = request.Name,
                Description = request.Description,
                PermissionIds = request.PermissionIds,
                CreatedAt = DateTime.UtcNow
            };

            _roles[role.Id] = role;

            return new UserManagementResponse<Role>
            {
                Success = true,
                Message = "Role created successfully",
                Data = role
            };
        }

        public async Task<UserManagementResponse<Role>> UpdateRoleAsync(string roleId, UpdateRoleRequest request)
        {
            await Task.Delay(100);

            if (!_roles.TryGetValue(roleId, out var role))
            {
                return new UserManagementResponse<Role>
                {
                    Success = false,
                    Message = "Role not found"
                };
            }

            if (role.IsSystemRole)
            {
                return new UserManagementResponse<Role>
                {
                    Success = false,
                    Message = "Cannot modify system roles"
                };
            }

            if (request.Description != null) role.Description = request.Description;
            if (request.PermissionIds != null) role.PermissionIds = request.PermissionIds;

            return new UserManagementResponse<Role>
            {
                Success = true,
                Message = "Role updated successfully",
                Data = role
            };
        }

        public async Task<UserManagementResponse<bool>> DeleteRoleAsync(string roleId)
        {
            await Task.Delay(100);

            if (!_roles.TryGetValue(roleId, out var role))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "Role not found"
                };
            }

            if (role.IsSystemRole)
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "Cannot delete system roles"
                };
            }

            // Remove role from all users
            foreach (var user in _users.Values)
            {
                user.RoleIds.Remove(roleId);
            }

            _roles.Remove(roleId);

            return new UserManagementResponse<bool>
            {
                Success = true,
                Message = "Role deleted successfully",
                Data = true
            };
        }

        public async Task<UserManagementResponse<RoleListResponse>> GetRolesAsync(int page = 1, int pageSize = 20)
        {
            await Task.Delay(100);

            var roles = _roles.Values.Skip((page - 1) * pageSize).Take(pageSize).ToList();
            var totalCount = _roles.Count;
            var totalPages = (int)Math.Ceiling((double)totalCount / pageSize);

            return new UserManagementResponse<RoleListResponse>
            {
                Success = true,
                Data = new RoleListResponse
                {
                    Roles = roles,
                    TotalCount = totalCount,
                    PageNumber = page,
                    PageSize = pageSize,
                    TotalPages = totalPages
                }
            };
        }

        public async Task<UserManagementResponse<bool>> ChangePasswordAsync(string userId, ChangePasswordRequest request)
        {
            await Task.Delay(100);

            if (!_users.TryGetValue(userId, out var user))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            if (!ValidatePassword(userId, request.CurrentPassword))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "Current password is incorrect"
                };
            }

            _userPasswords[userId] = HashPassword(request.NewPassword);
            user.PasswordChangedAt = DateTime.UtcNow;
            user.RequirePasswordChange = false;

            return new UserManagementResponse<bool>
            {
                Success = true,
                Message = "Password changed successfully",
                Data = true
            };
        }

        public async Task<UserManagementResponse<bool>> ResetPasswordAsync(ResetPasswordRequest request)
        {
            await Task.Delay(100);

            var user = _users.Values.FirstOrDefault(u => u.Email.Equals(request.Email, StringComparison.OrdinalIgnoreCase));
            
            if (user == null)
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            // Generate temporary password
            var tempPassword = GenerateTemporaryPassword();
            _userPasswords[user.Id] = HashPassword(tempPassword);
            user.RequirePasswordChange = true;
            user.PasswordChangedAt = DateTime.UtcNow;

            // In production, send email with temporary password
            // For demo purposes, we'll just return success

            return new UserManagementResponse<bool>
            {
                Success = true,
                Message = "Password reset email sent",
                Data = true
            };
        }

        public async Task<UserManagementResponse<bool>> LockUserAsync(string userId)
        {
            await Task.Delay(100);

            if (!_users.TryGetValue(userId, out var user))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            user.IsLocked = true;
            user.LockedUntil = DateTime.UtcNow.AddHours(24);

            return new UserManagementResponse<bool>
            {
                Success = true,
                Message = "User locked successfully",
                Data = true
            };
        }

        public async Task<UserManagementResponse<bool>> UnlockUserAsync(string userId)
        {
            await Task.Delay(100);

            if (!_users.TryGetValue(userId, out var user))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            user.IsLocked = false;
            user.LockedUntil = null;
            user.FailedLoginAttempts = 0;

            return new UserManagementResponse<bool>
            {
                Success = true,
                Message = "User unlocked successfully",
                Data = true
            };
        }

        public async Task<UserManagementResponse<bool>> AssignRoleToUserAsync(string userId, string roleId)
        {
            await Task.Delay(100);

            if (!_users.TryGetValue(userId, out var user))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            if (!_roles.TryGetValue(roleId, out var role))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "Role not found"
                };
            }

            if (!user.RoleIds.Contains(roleId))
            {
                user.RoleIds.Add(roleId);
            }

            return new UserManagementResponse<bool>
            {
                Success = true,
                Message = "Role assigned successfully",
                Data = true
            };
        }

        public async Task<UserManagementResponse<bool>> RemoveRoleFromUserAsync(string userId, string roleId)
        {
            await Task.Delay(100);

            if (!_users.TryGetValue(userId, out var user))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            if (!_roles.TryGetValue(roleId, out var role))
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "Role not found"
                };
            }

            if (role.IsSystemRole && role.Name == DashboardRoles.SuperAdmin)
            {
                return new UserManagementResponse<bool>
                {
                    Success = false,
                    Message = "Cannot remove super admin role"
                };
            }

            user.RoleIds.Remove(roleId);

            return new UserManagementResponse<bool>
            {
                Success = true,
                Message = "Role removed successfully",
                Data = true
            };
        }

        private void InitializeDefaultData()
        {
            // Initialize permissions
            var permissions = new List<Permission>
            {
                new Permission { Id = "1", Name = "View Executive Summary", Description = "View dashboard executive summary", Category = "Dashboard", Type = PermissionType.Read, Resource = "dashboard", Action = "executive.view" },
                new Permission { Id = "2", Name = "View Threats", Description = "View threat feed and analysis", Category = "Dashboard", Type = PermissionType.Read, Resource = "dashboard", Action = "threats.view" },
                new Permission { Id = "3", Name = "Manage Threats", Description = "Manage and respond to threats", Category = "Dashboard", Type = PermissionType.Write, Resource = "dashboard", Action = "threats.manage" },
                new Permission { Id = "4", Name = "View Endpoints", Description = "View endpoint information", Category = "Dashboard", Type = PermissionType.Read, Resource = "dashboard", Action = "endpoints.view" },
                new Permission { Id = "5", Name = "Manage Endpoints", Description = "Manage endpoint operations", Category = "Dashboard", Type = PermissionType.Write, Resource = "dashboard", Action = "endpoints.manage" },
                new Permission { Id = "6", Name = "Execute Actions", Description = "Execute dashboard actions", Category = "Dashboard", Type = PermissionType.Execute, Resource = "dashboard", Action = "actions.execute" },
                new Permission { Id = "7", Name = "View Users", Description = "View user list", Category = "Users", Type = PermissionType.Read, Resource = "users", Action = "view" },
                new Permission { Id = "8", Name = "Create Users", Description = "Create new users", Category = "Users", Type = PermissionType.Write, Resource = "users", Action = "create" },
                new Permission { Id = "9", Name = "Update Users", Description = "Update user information", Category = "Users", Type = PermissionType.Write, Resource = "users", Action = "update" },
                new Permission { Id = "10", Name = "Delete Users", Description = "Delete users", Category = "Users", Type = PermissionType.Delete, Resource = "users", Action = "delete" },
                new Permission { Id = "11", Name = "System Admin", Description = "Full system administration", Category = "System", Type = PermissionType.Admin, Resource = "system", Action = "admin" }
            };

            foreach (var permission in permissions)
            {
                _permissions[permission.Id] = permission;
            }

            // Initialize roles
            var superAdminRole = new Role
            {
                Id = "role-1",
                Name = DashboardRoles.SuperAdmin,
                Description = "Full system administrator with all permissions",
                IsSystemRole = true,
                PermissionIds = permissions.Select(p => p.Id).ToList()
            };

            var securityAdminRole = new Role
            {
                Id = "role-2",
                Name = DashboardRoles.SecurityAdmin,
                Description = "Security administrator with threat and endpoint management",
                IsSystemRole = true,
                PermissionIds = new List<string> { "1", "2", "3", "4", "5", "6", "7", "8", "9" }
            };

            var readOnlyRole = new Role
            {
                Id = "role-3",
                Name = DashboardRoles.ReadOnlyUser,
                Description = "Read-only access to dashboard",
                IsSystemRole = true,
                PermissionIds = new List<string> { "1", "2", "4" }
            };

            _roles[superAdminRole.Id] = superAdminRole;
            _roles[securityAdminRole.Id] = securityAdminRole;
            _roles[readOnlyRole.Id] = readOnlyRole;

            // Initialize default users
            var adminUser = new User
            {
                Id = "user-1",
                Email = "admin@phagevirus.com",
                Username = "admin",
                FullName = "System Administrator",
                Department = "IT",
                JobTitle = "System Administrator",
                IsActive = true,
                RoleIds = new List<string> { superAdminRole.Id },
                CreatedAt = DateTime.UtcNow
            };

            var securityUser = new User
            {
                Id = "user-2",
                Email = "security@phagevirus.com",
                Username = "security",
                FullName = "Security Manager",
                Department = "Security",
                JobTitle = "Security Manager",
                IsActive = true,
                RoleIds = new List<string> { securityAdminRole.Id },
                CreatedAt = DateTime.UtcNow
            };

            var analystUser = new User
            {
                Id = "user-3",
                Email = "analyst@phagevirus.com",
                Username = "analyst",
                FullName = "Security Analyst",
                Department = "Security",
                JobTitle = "Security Analyst",
                IsActive = true,
                RoleIds = new List<string> { readOnlyRole.Id },
                CreatedAt = DateTime.UtcNow
            };

            _users[adminUser.Id] = adminUser;
            _users[securityUser.Id] = securityUser;
            _users[analystUser.Id] = analystUser;

            // Set default passwords (in production, use proper password hashing)
            _userPasswords[adminUser.Id] = HashPassword("Admin@123");
            _userPasswords[securityUser.Id] = HashPassword("Security@123");
            _userPasswords[analystUser.Id] = HashPassword("Analyst@123");
        }

        private string GenerateToken()
        {
            return Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Replace("/", "_").Replace("+", "-").Substring(0, 22);
        }

        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hashedBytes);
        }

        private bool ValidatePassword(string userId, string password)
        {
            if (!_userPasswords.TryGetValue(userId, out var storedHash))
            {
                return false;
            }

            var inputHash = HashPassword(password);
            return storedHash == inputHash;
        }

        private List<string> GetUserPermissions(string userId)
        {
            if (!_users.TryGetValue(userId, out var user))
            {
                return new List<string>();
            }

            var permissions = new HashSet<string>();
            
            foreach (var roleId in user.RoleIds)
            {
                if (_roles.TryGetValue(roleId, out var role))
                {
                    foreach (var permissionId in role.PermissionIds)
                    {
                        if (_permissions.TryGetValue(permissionId, out var permission))
                        {
                            permissions.Add(permission.Name);
                        }
                    }
                }
            }

            return permissions.ToList();
        }

        private string GenerateTemporaryPassword()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 12).Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
} 