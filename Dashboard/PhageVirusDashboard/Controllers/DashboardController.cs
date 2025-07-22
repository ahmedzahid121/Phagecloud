using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using PhageVirusDashboard.Models;
using PhageVirusDashboard.Services;
using PhageVirusDashboard.Filters;

namespace PhageVirusDashboard.Controllers
{
    // Temporarily removed [RequireAuth] for testing - add back for production
    public class DashboardController : Controller
    {
        private readonly IDashboardService _dashboardService;

        public DashboardController(IDashboardService dashboardService)
        {
            _dashboardService = dashboardService;
        }

        public async Task<IActionResult> Index()
        {
            try
            {
                var dashboardData = await _dashboardService.GetDashboardDataAsync();
                return View(dashboardData);
            }
            catch (Exception ex)
            {
                // Log the error
                return View("Error", new ErrorViewModel { RequestId = ex.Message });
            }
        }

        // Temporarily removed permission requirements for testing
        public async Task<IActionResult> Endpoints(EndpointFilters? filters)
        {
            try
            {
                var endpoints = await _dashboardService.GetEndpointOverviewAsync(filters);
                return View(endpoints);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        public async Task<IActionResult> Threats()
        {
            try
            {
                var threatFeed = await _dashboardService.GetThreatFeedAsync();
                return View(threatFeed);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        public async Task<IActionResult> Cloud()
        {
            try
            {
                var cloudPosture = await _dashboardService.GetCloudPostureAsync();
                return View(cloudPosture);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        public async Task<IActionResult> Identity()
        {
            try
            {
                var identityProtection = await _dashboardService.GetIdentityProtectionAsync();
                return View(identityProtection);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        public async Task<IActionResult> Actions()
        {
            try
            {
                var actions = await _dashboardService.GetAvailableActionsAsync();
                return View(actions);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        public async Task<IActionResult> Logs()
        {
            try
            {
                var auditLogs = await _dashboardService.GetRecentAuditLogsAsync();
                return View(auditLogs);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        // API Endpoints for AJAX calls
        [HttpGet]
        public async Task<IActionResult> GetExecutiveSummary()
        {
            try
            {
                var summary = await _dashboardService.GetExecutiveSummaryAsync();
                return Json(new { success = true, data = summary });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetThreatFeed()
        {
            try
            {
                var threatFeed = await _dashboardService.GetThreatFeedAsync();
                return Json(new { success = true, data = threatFeed });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetEndpoints([FromQuery] EndpointFilters? filters)
        {
            try
            {
                var endpoints = await _dashboardService.GetEndpointOverviewAsync(filters);
                return Json(new { success = true, data = endpoints });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetCloudPosture()
        {
            try
            {
                var cloudPosture = await _dashboardService.GetCloudPostureAsync();
                return Json(new { success = true, data = cloudPosture });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetIdentityProtection()
        {
            try
            {
                var identityProtection = await _dashboardService.GetIdentityProtectionAsync();
                return Json(new { success = true, data = identityProtection });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetDashboardStats()
        {
            try
            {
                var stats = await _dashboardService.GetDashboardStatsAsync();
                return Json(new { success = true, data = stats });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        public async Task<IActionResult> ExecuteAction([FromBody] ActionRequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request.ActionId))
                {
                    return Json(new { success = false, message = "Action ID is required" });
                }

                var parameters = request.Parameters ?? new Dictionary<string, object>();
                var result = await _dashboardService.ExecuteActionAsync(request.ActionId, parameters);

                return Json(result);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetAuditLogs()
        {
            try
            {
                var auditLogs = await _dashboardService.GetRecentAuditLogsAsync();
                return Json(new { success = true, data = auditLogs });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> ExportLogs([FromQuery] string format = "csv", [FromQuery] string dateRange = "24h")
        {
            try
            {
                var auditLogs = await _dashboardService.GetRecentAuditLogsAsync();
                
                if (format.ToLower() == "csv")
                {
                    var csvContent = GenerateCsvContent(auditLogs);
                    return File(System.Text.Encoding.UTF8.GetBytes(csvContent), "text/csv", $"audit_logs_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
                }
                else if (format.ToLower() == "json")
                {
                    return Json(auditLogs);
                }
                else
                {
                    return BadRequest("Unsupported format. Use 'csv' or 'json'.");
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        private string GenerateCsvContent(List<AuditLog> auditLogs)
        {
            var csv = "Timestamp,User,Action,Resource,Details,IP Address,Success\n";
            
            foreach (var log in auditLogs)
            {
                csv += $"\"{log.Timestamp:yyyy-MM-dd HH:mm:ss}\",\"{log.User}\",\"{log.Action}\",\"{log.Resource}\",\"{log.Details}\",\"{log.IpAddress}\",\"{log.Success}\"\n";
            }
            
            return csv;
        }
    }

    public class ActionRequest
    {
        public string ActionId { get; set; } = string.Empty;
        public Dictionary<string, object>? Parameters { get; set; }
    }

    public class ErrorViewModel
    {
        public string? RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
    }
} 