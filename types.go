package main

import "time"

// Constants
const (
	VIN_LENGTH    = 11
	MAX_VIN_CHARS = 20 // VIN + PREFIX combined
	MAX_USERNAME  = 50
	MAX_PASSWORD  = 100
	SESSION_HOURS = 8
)

// Project detection prefixes
const (
	TAN_PREFIX = "TAN" // V710_PROJECT
	TAR_PREFIX = "TAR" // J74_PROJECT
)

// File type constants
const (
	FILE_TYPE_VPL = "VPL"
	FILE_TYPE_TEI = "TEI"
	FILE_TYPE_OSL = "OSL"
)

// Issue type constants
const (
	// VPL issue types

	// Master data issue types
	MD_ISSUE_TEI_NOT_FOUND  = "TEI_NOT_FOUND"
	MD_ISSUE_INNER_MISMATCH = "INNER_MISMATCH"
	MD_ISSUE_NO_DESCRIPTION = "NO_DESCRIPTION"
	MD_ISSUE_OSL_NOT_FOUND  = "OSL_NOT_FOUND"
	MD_ISSUE_MISSING_PARAMS = "MISSING_PARAMS"
	MD_ISSUE_CK_VIOLATION   = "CK_VIOLATION"
)

// =============================================================================
// DATABASE RECORDS (What we store - only problems/issues)
// =============================================================================

// VPL Issue - stored in database (only when there's a problem)
type VPLIssue struct {
	Date        string `json:"date"`         // "2024-12-15"
	VIN         string `json:"vin"`          // "TANLSA12917"
	Project     string `json:"project"`      // "V710_PROJECT"
	IssueType   string `json:"issue_type"`   // "ADDED", "REMOVED", "CHANGED", "MISSING_REQUIRED"
	OldPart     string `json:"old_part"`     // Empty if ADDED
	NewPart     string `json:"new_part"`     // Empty if REMOVED
	MissingPart string `json:"missing_part"` // For MISSING_REQUIRED
	Details     string `json:"details"`      // Additional info
}

// Master Data Issue - stored in database (only violations/problems)
type MasterDataIssue struct {
	Date      string `json:"date"`       // "2024-12-15"
	PartName  string `json:"part_name"`  // "MPZ3T18K811CF3JA6"
	InnerRef  string `json:"inner_ref"`  // "EMPZ3T18K811CF3JA6"
	IssueType string `json:"issue_type"` // "TEI_NOT_FOUND", "CK_VIOLATION", etc.
	Expected  string `json:"expected"`   // What should be
	Actual    string `json:"actual"`     // What was found
	Details   string `json:"details"`    // Error description
}

// =============================================================================
// RUNTIME STRUCTURES (What backend parses from files - not stored)
// =============================================================================

// VPL Record - parsed from file (runtime only, not stored)
type VPLRecord struct {
	VIN             string `json:"vin"`              // "TANLSA12917"
	Prefix          string `json:"prefix"`           // "MPZ3T"
	Base            string `json:"base"`             // "18K811"
	Suffix          string `json:"suffix"`           // "CF3JA6"
	Quantity        string `json:"quantity"`         // "001.00000"
	PartName        string `json:"part_name"`        // Generated: Prefix+Base+Suffix
	DetectedProject string `json:"detected_project"` // "V710_PROJECT" or "J74_PROJECT"
}

// TEI Record - parsed from file (runtime only)
type TEIRecord struct {
	CustomerReference string `json:"customer_reference"`
	InnerReference    string `json:"inner_reference"`
	PartDescription   string `json:"part_description"`
}

// OSL Record - parsed from file (runtime only)
type OSLRecord struct {
	InnerReference string `json:"inner_reference"`
	ParameterName  string `json:"parameter_name"`
	ParameterValue string `json:"parameter_value"`
}

// =============================================================================
// FRONTEND SUMMARY (Calculated from database issues)
// =============================================================================

// VPL Analysis Summary - what frontend sees first (calculated from VPLIssue table)
type VPLAnalysisSummary struct {
	Date              string `json:"date"`
	TotalVINsAnalyzed int    `json:"total_vins_analyzed"` // Total processed (from file)
	IssuesFound       int    `json:"issues_found"`        // COUNT(*) FROM vpl_issues
	ChangesCount      int    `json:"changes_count"`       // ADDED + REMOVED + CHANGED
	MissingReqCount   int    `json:"missing_req_count"`   // MISSING_REQUIRED count
	AffectedVINs      int    `json:"affected_vins"`       // COUNT(DISTINCT vin)
	ProcessingTime    string `json:"processing_time"`
	HasIssues         bool   `json:"has_issues"` // issues_found > 0
}

type MasterDataStats struct {
	TotalVPLParts               int
	FoundInTEI                  int
	TEIMatchRate                float64
	InnerRefAccuracy            float64
	DescriptionCoverage         float64
	TotalParts                  int
	FoundInOSL                  int
	OSLMatchRate                float64
	ParameterCompleteness       float64
	RequiredParamComplianceRate float64
	ProjectComplianceRate       float64
	CKTotalParts                int
}

type Config struct {
	Database    DatabaseConfig   `json:"database"`
	FileSources FileSourceConfig `json:"file_sources"`
	LocalPaths  LocalPathConfig  `json:"local_paths"`
	Server      ServerConfig     `json:"server"`
}

type DatabaseConfig struct {
	ConnectionString string `json:"connection_string"`
}

type FileSourceConfig struct {
	VPLSourcePath       string `json:"vpl_source_path"`
	TEISourcePath       string `json:"tei_source_path"`
	OSLSourcePath       string `json:"osl_source_path"`
	CopyIntervalMinutes int    `json:"copy_interval_minutes"`
}

type LocalPathConfig struct {
	VPLFiles        string `json:"vpl_files"`
	MasterDataFiles string `json:"masterdata_files"`
}

type ServerConfig struct {
	Port        string `json:"port"`
	AutoAnalyze bool   `json:"auto_analyze"`
}

// Master Data Analysis Summary - what frontend sees first (calculated from MasterDataIssue table)
type MasterDataAnalysisSummary struct {
	Date               string  `json:"date"`
	TotalPartsAnalyzed int     `json:"total_parts_analyzed"` // Total processed (from file)
	IssuesFound        int     `json:"issues_found"`         // COUNT(*) FROM masterdata_issues
	TEIIssuesCount     int     `json:"tei_issues_count"`     // TEI related issues
	OSLIssuesCount     int     `json:"osl_issues_count"`     // OSL related issues
	CKViolationsCount  int     `json:"ck_violations_count"`  // CK specific violations
	AffectedPartsCount int     `json:"affected_parts_count"` // COUNT(DISTINCT part_name)
	ComplianceRate     float64 `json:"compliance_rate"`      // (total-issues)/total * 100
	HasIssues          bool    `json:"has_issues"`           // issues_found > 0
}

// =============================================================================
// FRONTEND DETAIL MODALS (What user sees when clicking issue counts)
// =============================================================================

// VPL Issues Modal - when user clicks "250 Issues Found"

type VPLIssuesModal struct {
	Issues      []VPLIssueDetail `json:"issues"`
	TotalCount  int              `json:"total_count"`
	Page        int              `json:"page"`
	PageSize    int              `json:"page_size"`
	SearchQuery string           `json:"search_query"`
	FilterType  string           `json:"filter_type"` // "ALL", "CHANGES", "MISSING_REQ"
}

// VPL Issue Detail - single row in modal (from database)
type VPLIssueDetail struct {
	VIN           string `json:"vin"`
	Project       string `json:"project"`
	IssueType     string `json:"issue_type"`
	OldPart       string `json:"old_part,omitempty"`
	NewPart       string `json:"new_part,omitempty"`
	MissingPart   string `json:"missing_part,omitempty"`
	Details       string `json:"details,omitempty"`
	HighlightText string `json:"highlight_text,omitempty"` // For search highlighting
}

// Master Data Issues Modal - when user clicks "45 Issues Found"
type MasterDataIssuesModal struct {
	Issues      []MasterDataIssueDetail `json:"issues"`
	TotalCount  int                     `json:"total_count"`
	Page        int                     `json:"page"`
	PageSize    int                     `json:"page_size"`
	SearchQuery string                  `json:"search_query"`
	FilterType  string                  `json:"filter_type"` // "ALL", "TEI", "OSL", "CK"
}

// Master Data Issue Detail - single row in modal (from database)
type MasterDataIssueDetail struct {
	PartName      string `json:"part_name"`
	InnerRef      string `json:"inner_ref"`
	IssueType     string `json:"issue_type"`
	Expected      string `json:"expected,omitempty"`
	Actual        string `json:"actual,omitempty"`
	Details       string `json:"details"`
	HighlightText string `json:"highlight_text,omitempty"`
}

// =============================================================================
// SEARCH REQUESTS (What frontend sends for filtering/pagination)
// =============================================================================

// VPL Issues Search Request
type VPLIssuesSearchRequest struct {
	Date       string `json:"date"`
	Query      string `json:"query"`       // Search in VIN, parts
	FilterType string `json:"filter_type"` // "ALL", "CHANGES", "MISSING_REQ"
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
}

// Master Data Issues Search Request
type MasterDataIssuesSearchRequest struct {
	Date       string `json:"date"`
	Query      string `json:"query"`       // Search in part names, inner refs
	FilterType string `json:"filter_type"` // "ALL", "TEI", "OSL", "CK"
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
}

// =============================================================================
// SYSTEM TYPES (Authentication, Config, etc.)
// =============================================================================

// User for authentication
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// Session for login management
type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// API Response wrapper
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Required parts configuration (project-based, stored in database)
type RequiredPart struct {
	ProjectName  string `json:"project_name"`  // "V710_PROJECT", "J74_PROJECT"
	RequiredPart string `json:"required_part"` // "18K811" or "!A-OR-B!"
}

// File copy configuration
type CopyConfig struct {
	ServerPath   string `json:"server_path"`   // "\\\\server\\share\\files\\"
	LocalPath    string `json:"local_path"`    // "./files/"
	CopyInterval int    `json:"copy_interval"` // Minutes
	AutoAnalyze  bool   `json:"auto_analyze"`  // Auto analyze after copy
}

// File info for processing
type FileInfo struct {
	FileName string    `json:"file_name"`
	FilePath string    `json:"file_path"`
	FileType string    `json:"file_type"` // "VPL", "TEI", "OSL"
	Date     string    `json:"date"`      // Extracted from filename
	Size     int64     `json:"size"`
	ModTime  time.Time `json:"mod_time"`
}

const (
	// VPL issue types - existing
	VPL_ISSUE_ADDED       = "ADDED"
	VPL_ISSUE_REMOVED     = "REMOVED"
	VPL_ISSUE_CHANGED     = "CHANGED" // Keep for backward compatibility
	VPL_ISSUE_MISSING_REQ = "MISSING_REQUIRED"

	// VPL component change types - new
	VPL_ISSUE_PREFIX_CHANGED = "PREFIX_CHANGED"
	VPL_ISSUE_BASE_CHANGED   = "BASE_CHANGED"
	VPL_ISSUE_SUFFIX_CHANGED = "SUFFIX_CHANGED"
)

type ChangeGroup struct {
	ChangeType   string   `json:"change_type"`
	OldPartName  string   `json:"old_part_name"`
	NewPartName  string   `json:"new_part_name"`
	ChangeDetail string   `json:"change_detail"`
	AffectedVins []string `json:"affected_vins"`
}
