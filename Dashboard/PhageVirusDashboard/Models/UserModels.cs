using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PhageVirusDashboard.Models
{
    // User Management Models
    public class User
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        
        [Required]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        public string FullName { get; set; } = string.Empty;
        
        public string? Department { get; set; }
        
        public string? JobTitle { get; set; }
        
        public string? PhoneNumber { get; set; }
        
        public bool IsActive { get; set; } = true;
        
        public bool IsLocked { get; set; } = false;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        
        public DateTime? LastLoginAt { get; set; }
        
        public DateTime? PasswordChangedAt { get; set; }
        
        public int FailedLoginAttempts { get; set; } = 0;
        
        public DateTime? LockedUntil { get; set; }
        
        public List<string> RoleIds { get; set; } = new();
        
        public List<string> PermissionIds { get; set; } = new();
        
        public string? ProfilePictureUrl { get; set; }
        
        public bool RequirePasswordChange { get; set; } = false;
        
        public string? TwoFactorSecret { get; set; }
        
        public bool TwoFactorEnabled { get; set; } = false;
    }

    public class Role
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        [Required]
        public string Name { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public bool IsSystemRole { get; set; } = false;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        
        public List<string> PermissionIds { get; set; } = new();
        
        public List<string> UserIds { get; set; } = new();
    }

    public class Permission
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        [Required]
        public string Name { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public string Category { get; set; } = string.Empty;
        
        public PermissionType Type { get; set; }
        
        public string Resource { get; set; } = string.Empty;
        
        public string Action { get; set; } = string.Empty;
    }

    public enum PermissionType
    {
        Read,
        Write,
        Delete,
        Execute,
        Admin
    }

    // Authentication Models
    public class LoginRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        
        [Required]
        public string Password { get; set; } = string.Empty;
        
        public bool RememberMe { get; set; } = false;
        
        public string? TwoFactorCode { get; set; }
    }

    public class LoginResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? Token { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public UserInfo? User { get; set; }
        public bool RequiresTwoFactor { get; set; } = false;
    }

    public class UserInfo
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public List<string> Roles { get; set; } = new();
        public List<string> Permissions { get; set; } = new();
        public string? ProfilePictureUrl { get; set; }
        public bool RequirePasswordChange { get; set; } = false;
    }

    public class ChangePasswordRequest
    {
        [Required]
        public string CurrentPassword { get; set; } = string.Empty;
        
        [Required]
        [MinLength(8)]
        public string NewPassword { get; set; } = string.Empty;
        
        [Required]
        [Compare("NewPassword")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class ResetPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }

    public class CreateUserRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        
        [Required]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        public string FullName { get; set; } = string.Empty;
        
        [Required]
        [MinLength(8)]
        public string Password { get; set; } = string.Empty;
        
        public string? Department { get; set; }
        
        public string? JobTitle { get; set; }
        
        public string? PhoneNumber { get; set; }
        
        public List<string> RoleIds { get; set; } = new();
        
        public bool RequirePasswordChange { get; set; } = true;
    }

    public class UpdateUserRequest
    {
        public string? FullName { get; set; }
        public string? Department { get; set; }
        public string? JobTitle { get; set; }
        public string? PhoneNumber { get; set; }
        public bool? IsActive { get; set; }
        public List<string>? RoleIds { get; set; }
        public string? ProfilePictureUrl { get; set; }
    }

    public class CreateRoleRequest
    {
        [Required]
        public string Name { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public List<string> PermissionIds { get; set; } = new();
    }

    public class UpdateRoleRequest
    {
        public string? Description { get; set; }
        public List<string>? PermissionIds { get; set; }
    }

    // Dashboard Permission Categories
    public static class DashboardPermissions
    {
        // Executive Summary
        public const string ViewExecutiveSummary = "dashboard.executive.view";
        public const string ExportExecutiveSummary = "dashboard.executive.export";
        
        // Threat Management
        public const string ViewThreats = "dashboard.threats.view";
        public const string ManageThreats = "dashboard.threats.manage";
        public const string ExportThreats = "dashboard.threats.export";
        
        // Endpoint Management
        public const string ViewEndpoints = "dashboard.endpoints.view";
        public const string ManageEndpoints = "dashboard.endpoints.manage";
        public const string IsolateEndpoints = "dashboard.endpoints.isolate";
        public const string UpdateEndpoints = "dashboard.endpoints.update";
        
        // Cloud Security
        public const string ViewCloudPosture = "dashboard.cloud.view";
        public const string ManageCloudPosture = "dashboard.cloud.manage";
        public const string ExportCloudReports = "dashboard.cloud.export";
        
        // Identity Protection
        public const string ViewIdentityProtection = "dashboard.identity.view";
        public const string ManageIdentityProtection = "dashboard.identity.manage";
        public const string ExportIdentityReports = "dashboard.identity.export";
        
        // Actions
        public const string ExecuteActions = "dashboard.actions.execute";
        public const string ViewActions = "dashboard.actions.view";
        
        // Audit Logs
        public const string ViewAuditLogs = "dashboard.audit.view";
        public const string ExportAuditLogs = "dashboard.audit.export";
        
        // User Management
        public const string ViewUsers = "users.view";
        public const string CreateUsers = "users.create";
        public const string UpdateUsers = "users.update";
        public const string DeleteUsers = "users.delete";
        public const string ManageUserRoles = "users.roles.manage";
        
        // Role Management
        public const string ViewRoles = "roles.view";
        public const string CreateRoles = "roles.create";
        public const string UpdateRoles = "roles.update";
        public const string DeleteRoles = "roles.delete";
        
        // System Administration
        public const string SystemAdmin = "system.admin";
        public const string ViewSystemLogs = "system.logs.view";
        public const string ManageSystemSettings = "system.settings.manage";
    }

    // Predefined Roles
    public static class DashboardRoles
    {
        public const string SuperAdmin = "SuperAdmin";
        public const string SecurityAdmin = "SecurityAdmin";
        public const string SecurityAnalyst = "SecurityAnalyst";
        public const string EndpointManager = "EndpointManager";
        public const string CloudSecurityManager = "CloudSecurityManager";
        public const string IdentityManager = "IdentityManager";
        public const string ReadOnlyUser = "ReadOnlyUser";
        public const string Auditor = "Auditor";
    }

    // Session Models
    public class UserSession
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string UserId { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresAt { get; set; }
        public string IpAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public bool IsActive { get; set; } = true;
    }

    // API Response Models
    public class UserManagementResponse<T>
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public T? Data { get; set; }
        public List<string> Errors { get; set; } = new();
    }

    public class UserListResponse
    {
        public List<User> Users { get; set; } = new();
        public int TotalCount { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public int TotalPages { get; set; }
    }

    public class RoleListResponse
    {
        public List<Role> Roles { get; set; } = new();
        public int TotalCount { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public int TotalPages { get; set; }
    }
} 