using System;

namespace PhageVirus.Modules
{
    public class ThreatData
    {
        public string ThreatHash { get; set; } = "";
        public string ThreatType { get; set; } = "";
        public string TargetPath { get; set; } = "";
        public string ThreatLevel { get; set; } = "";
        public string NodeId { get; set; } = "";
        public DateTime DetectedAt { get; set; } = DateTime.Now;
        public string Description { get; set; } = "";
        public string Source { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public string Details { get; set; } = "";
    }
} 
