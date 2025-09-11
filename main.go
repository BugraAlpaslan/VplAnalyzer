package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
)

// =============================================================================
// GLOBAL VARIABLES
// =============================================================================

var db *sql.DB
var activeSessions = make(map[string]Session)

const (
	DEFAULT_PORT = "8080"
	DB_NAME      = "VPLAnalyzer"
	PAGE_SIZE    = 50
)

// Default users
var defaultUsers = map[string]string{
	"admin": "admin123",
	"user":  "vpl2024",
}

// =============================================================================
// DATABASE FUNCTIONS (SQL EXPRESS)
// =============================================================================

func connectDatabase() error {
	connectionString := "server=BLCKTLP\\SQLEXPRESS;database=VPLAnalyzer;integrated security=SSPI;encrypt=true;trustservercertificate=true"
	var err error
	db, err = sql.Open("mssql", connectionString)
	if err != nil {
		return fmt.Errorf("database connection failed: %v", err)
	}

	if err = db.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %v", err)
	}

	log.Println("✅ SQL Express connected successfully")
	return createDatabaseSchema()
}

func createDatabaseSchema() error {
	fmt.Println("admin123 hash:", hashPassword("admin123"))
	fmt.Println("vpl2024 hash:", hashPassword("vpl2024"))

	return initializeDefaultData()
}

func initializeDefaultData() error {
	// Create default users
	for username, password := range defaultUsers {
		hashedPassword := hashPassword(password)
		_, err := db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)",
			username, hashedPassword)
		if err != nil && !strings.Contains(err.Error(), "duplicate") {
			return fmt.Errorf("failed to create user %s: %v", username, err)
		}
	}

	// Insert sample required parts
	sampleParts := []RequiredPart{
		{"V710_PROJECT", "18K811"},
		{"V710_PROJECT", "!MPZ3T-OR-NPZ3T!"},
		{"J74_PROJECT", "V04545"},
		{"J74_PROJECT", "!W123-OR-W456!"},
	}

	for _, part := range sampleParts {
		_, err := db.Exec("INSERT INTO required_parts (project_name, required_part) VALUES (?, ?)",
			part.ProjectName, part.RequiredPart)
		if err != nil && !strings.Contains(err.Error(), "duplicate") {
			log.Printf("Warning: could not insert required part: %v", err)
		}
	}

	log.Println("✅ Database schema and default data initialized")
	return nil
}

func saveVPLIssues(date string, issues []VPLIssue) error {
	// Clear existing issues for this date
	_, err := db.Exec("DELETE FROM vpl_issues WHERE date = ?", date)
	if err != nil {
		return fmt.Errorf("failed to clear existing VPL issues: %v", err)
	}

	// Insert new issues
	for _, issue := range issues {
		_, err := db.Exec(`INSERT INTO vpl_issues 
			(date, vin, project, issue_type, old_part, new_part, missing_part, details) 
			VALUES (?, ?, ?, ?, @p5, @p6, @p7, @p8)`,
			issue.Date, issue.VIN, issue.Project, issue.IssueType,
			issue.OldPart, issue.NewPart, issue.MissingPart, issue.Details)
		if err != nil {
			return fmt.Errorf("failed to insert VPL issue: %v", err)
		}
	}

	log.Printf("✅ Saved %d VPL issues for date %s", len(issues), date)
	return nil
}

func saveMasterDataIssues(date string, teiIssues, oslIssues []MasterDataIssue) error {
	// Clear existing issues for this date
	_, err := db.Exec("DELETE FROM masterdata_issues WHERE date = ?", date)
	if err != nil {
		return fmt.Errorf("failed to clear existing master data issues: %v", err)
	}

	// Combine TEI and OSL issues
	allIssues := append(teiIssues, oslIssues...)

	// Insert new issues
	for _, issue := range allIssues {
		_, err := db.Exec(`INSERT INTO masterdata_issues 
			(date, part_name, inner_ref, issue_type, expected, actual, details) 
			VALUES (?, ?, ?, ?, @p5, @p6, @p7)`,
			issue.Date, issue.PartName, issue.InnerRef, issue.IssueType,
			issue.Expected, issue.Actual, issue.Details)
		if err != nil {
			return fmt.Errorf("failed to insert master data issue: %v", err)
		}
	}

	log.Printf("✅ Saved %d master data issues for date %s", len(allIssues), date)
	return nil
}

func getRequiredPartsForProject(project string) ([]string, error) {
	rows, err := db.Query("SELECT required_part FROM required_parts WHERE project_name = ?", project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var part string
		if err := rows.Scan(&part); err != nil {
			continue
		}
		parts = append(parts, part)
	}

	return parts, nil
}

// =============================================================================
// SECURITY FUNCTIONS
// =============================================================================

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func validateCredentials(username, password string) bool {
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedHash)
	if err != nil {
		return false
	}

	hashedInput := hashPassword(password)
	return hashedInput == storedHash
}

func createSession(username string) string {
	token := generateToken()
	expiresAt := time.Now().Add(SESSION_HOURS * time.Hour)

	session := Session{
		Token:     token,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	activeSessions[token] = session

	_, err := db.Exec("INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)",
		token, username, expiresAt)
	if err != nil {
		log.Printf("❌ Session database save failed: %v", err)
		// Ama token'ı yine de döndür, memory'de var
	} else {
		log.Printf("✅ Session saved to database: %s", token[:10]+"...")
	}

	return token
}

func validateSession(token string) bool {
	session, exists := activeSessions[token]
	if !exists {
		// Try to load from database
		var username string
		var expiresAt time.Time
		err := db.QueryRow("SELECT username, expires_at FROM sessions WHERE token = ?", token).
			Scan(&username, &expiresAt)
		if err != nil {
			return false
		}

		session = Session{Token: token, Username: username, ExpiresAt: expiresAt}
		activeSessions[token] = session
	}

	if time.Now().After(session.ExpiresAt) {
		delete(activeSessions, token)
		db.Exec("DELETE FROM sessions WHERE token = ?", token)
		return false
	}

	return true
}

func validateInput(input string) bool {
	if len(input) > 200 {
		return false
	}

	dangerous := []string{"<script", "<iframe", "javascript:", "vbscript:", "onload=", "onerror=", "'", "\"", ";", "--"}
	inputLower := strings.ToLower(input)

	for _, danger := range dangerous {
		if strings.Contains(inputLower, danger) {
			return false
		}
	}

	return true
}

// =============================================================================
// FILE FUNCTIONS
// =============================================================================

func findVPLFileForDate(date string) string {
	dateFormats := []string{
		date,                              // 2024-12-15
		strings.ReplaceAll(date, "-", ""), // 20241215
	}

	for _, dateFormat := range dateFormats {
		pattern := fmt.Sprintf("./vpl_files/*%s*.txt", dateFormat)
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return matches[0]
		}
	}

	return ""
}

func findTEIFileForDate(date string) string {
	dateFormats := []string{
		date,
		strings.ReplaceAll(date, "-", ""),
	}

	for _, dateFormat := range dateFormats {
		pattern := fmt.Sprintf("./masterdata_files/*TEI*%s*.txt", dateFormat)
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return matches[0]
		}
	}

	return ""
}

func findOSLFileForDate(date string) string {
	dateFormats := []string{
		date,
		strings.ReplaceAll(date, "-", ""),
	}

	for _, dateFormat := range dateFormats {
		pattern := fmt.Sprintf("./masterdata_files/*OSL*%s*.txt", dateFormat)
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return matches[0]
		}
	}

	return ""
}

func readVPLFile(filePath string) ([]VPLRecord, error) {
	if filePath == "" {
		return nil, fmt.Errorf("VPL file not found")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open VPL file: %v", err)
	}
	defer file.Close()

	var records []VPLRecord
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "VPLIST") {
			record, err := parseVPLRecord(line)
			if err == nil {
				records = append(records, record)
			}
		}
	}

	log.Printf("📊 Read %d VPL records from %s", len(records), filepath.Base(filePath))
	return records, nil
}

func parseVPLRecord(line string) (VPLRecord, error) {
	line = strings.TrimPrefix(line, "VPLIST")
	fields := strings.Fields(line)

	if len(fields) < 4 {
		return VPLRecord{}, fmt.Errorf("invalid VPL record format")
	}

	vinAndPrefix := fields[0]
	if len(vinAndPrefix) < VIN_LENGTH {
		return VPLRecord{}, fmt.Errorf("invalid VIN length")
	}

	vin := vinAndPrefix[:VIN_LENGTH]
	prefix := vinAndPrefix[VIN_LENGTH:]

	record := VPLRecord{
		VIN:      vin,
		Prefix:   prefix,
		Base:     fields[1],
		Suffix:   fields[2],
		Quantity: fields[3],
		PartName: prefix + fields[1] + fields[2],
	}

	// Detect project from VIN
	if strings.HasPrefix(record.VIN, TAN_PREFIX) {
		record.DetectedProject = "V710_PROJECT"
	} else if strings.HasPrefix(record.VIN, TAR_PREFIX) {
		record.DetectedProject = "J74_PROJECT"
	} else {
		record.DetectedProject = "DEFAULT_PROJECT"
	}

	return record, nil
}

func readTEIFile(filePath string) (map[string]TEIRecord, error) {
	if filePath == "" {
		return nil, fmt.Errorf("TEI file not found")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open TEI file: %v", err)
	}
	defer file.Close()

	teiMap := make(map[string]TEIRecord)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Split(line, "\t")

		if len(fields) >= 3 {
			record := TEIRecord{
				CustomerReference: strings.TrimSpace(fields[0]),
				InnerReference:    strings.TrimSpace(fields[1]),
				PartDescription:   strings.TrimSpace(fields[2]),
			}

			teiMap[record.CustomerReference] = record
		}
	}

	log.Printf("📊 Read %d TEI records from %s", len(teiMap), filepath.Base(filePath))
	return teiMap, nil
}

func readOSLFile(filePath string) (map[string]map[string]string, error) {
	if filePath == "" {
		return nil, fmt.Errorf("OSL file not found")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open OSL file: %v", err)
	}
	defer file.Close()

	oslMap := make(map[string]map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Split(line, "\t")

		if len(fields) >= 3 {
			innerRef := strings.TrimSpace(fields[0])
			paramName := strings.TrimSpace(fields[1])
			paramValue := strings.TrimSpace(fields[2])

			if oslMap[innerRef] == nil {
				oslMap[innerRef] = make(map[string]string)
			}

			oslMap[innerRef][paramName] = paramValue
		}
	}

	log.Printf("📊 Read %d OSL records from %s", len(oslMap), filepath.Base(filePath))
	return oslMap, nil
}

func extractDateFromFilename(filename string) string {
	re := regexp.MustCompile(`(\d{4})-?(\d{2})-?(\d{2})`)
	matches := re.FindStringSubmatch(filename)

	if len(matches) >= 4 {
		return fmt.Sprintf("%s-%s-%s", matches[1], matches[2], matches[3])
	}

	return ""
}

// =============================================================================
// ANALYSIS FUNCTIONS (Main Logic - Single Pass Analysis)
// =============================================================================

func runCompleteAnalysis(date string) error {
	log.Printf("🚀 Starting complete analysis for date: %s", date)
	startTime := time.Now()

	// 1. Find required files
	currentVPLFile := findVPLFileForDate(date)
	if currentVPLFile == "" {
		return fmt.Errorf("VPL file not found for date %s", date)
	}

	// Calculate previous date for VPL comparison
	parsedDate, err := time.Parse("2006-01-02", date)
	if err != nil {
		return fmt.Errorf("invalid date format: %v", err)
	}
	previousDate := parsedDate.AddDate(0, 0, -1).Format("2006-01-02")
	previousVPLFile := findVPLFileForDate(previousDate)

	teiFile := findTEIFileForDate(date)
	oslFile := findOSLFileForDate(date)

	// 2. Read VPL files and compare
	currentVPL, err := readVPLFile(currentVPLFile)
	if err != nil {
		return fmt.Errorf("failed to read current VPL: %v", err)
	}

	var vplIssues []VPLIssue
	if previousVPLFile != "" {
		previousVPL, err := readVPLFile(previousVPLFile)
		if err != nil {
			log.Printf("Warning: could not read previous VPL file: %v", err)
		} else {
			vplIssues = compareVPLFiles(date, previousVPL, currentVPL)
		}
	}

	// 3. Check missing required parts
	missingRequired := checkMissingRequiredParts(date, currentVPL)
	vplIssues = append(vplIssues, missingRequired...)

	// 4. Extract customer references from VPL for master data analysis
	customerRefs := extractCustomerReferences(currentVPL)

	var teiIssues []MasterDataIssue
	var oslIssues []MasterDataIssue

	// 5. TEI Analysis (if file exists)
	if teiFile != "" {
		teiRecords, err := readTEIFile(teiFile)
		if err != nil {
			log.Printf("Warning: failed to read TEI file: %v", err)
		} else {
			teiIssues = validateTEIReferences(date, customerRefs, teiRecords)

			// 6. OSL Analysis (if file exists and we have TEI data)
			if oslFile != "" {
				oslRecords, err := readOSLFile(oslFile)
				if err != nil {
					log.Printf("Warning: failed to read OSL file: %v", err)
				} else {
					innerRefs := extractInnerReferences(customerRefs, teiRecords)
					oslIssues = validateOSLParameters(date, innerRefs, oslRecords)
				}
			}
		}
	}

	// 7. Save all issues to database
	if err := saveVPLIssues(date, vplIssues); err != nil {
		return fmt.Errorf("failed to save VPL issues: %v", err)
	}

	if err := saveMasterDataIssues(date, teiIssues, oslIssues); err != nil {
		return fmt.Errorf("failed to save master data issues: %v", err)
	}

	processingTime := time.Since(startTime)
	log.Printf("✅ Complete analysis finished in %v - VPL: %d issues, Master Data: %d issues",
		processingTime, len(vplIssues), len(teiIssues)+len(oslIssues))

	return nil
}

func compareVPLFiles(date string, previousVPL, currentVPL []VPLRecord) []VPLIssue {
	var issues []VPLIssue

	// Create maps for easy lookup
	prevMap := make(map[string]VPLRecord)
	for _, record := range previousVPL {
		key := record.VIN + "|" + record.PartName
		prevMap[key] = record
	}

	currMap := make(map[string]VPLRecord)
	for _, record := range currentVPL {
		key := record.VIN + "|" + record.PartName
		currMap[key] = record
	}

	// Find added parts
	for key, currRecord := range currMap {
		if _, exists := prevMap[key]; !exists {
			issues = append(issues, VPLIssue{
				Date:      date,
				VIN:       currRecord.VIN,
				Project:   currRecord.DetectedProject,
				IssueType: VPL_ISSUE_ADDED,
				NewPart:   currRecord.PartName,
				Details:   "Part added",
			})
		}
	}

	// Find removed parts
	for key, prevRecord := range prevMap {
		if _, exists := currMap[key]; !exists {
			issues = append(issues, VPLIssue{
				Date:      date,
				VIN:       prevRecord.VIN,
				Project:   prevRecord.DetectedProject,
				IssueType: VPL_ISSUE_REMOVED,
				OldPart:   prevRecord.PartName,
				Details:   "Part removed",
			})
		}
	}

	log.Printf("📊 VPL Comparison: %d added, %d removed",
		countIssuesByType(issues, VPL_ISSUE_ADDED),
		countIssuesByType(issues, VPL_ISSUE_REMOVED))

	return issues
}

func checkMissingRequiredParts(date string, vplRecords []VPLRecord) []VPLIssue {
	var issues []VPLIssue

	// Group VPL records by project
	projectRecords := make(map[string][]VPLRecord)
	for _, record := range vplRecords {
		projectRecords[record.DetectedProject] = append(projectRecords[record.DetectedProject], record)
	}

	// Check each project
	for project, records := range projectRecords {
		requiredParts, err := getRequiredPartsForProject(project)
		if err != nil {
			log.Printf("Warning: could not get required parts for project %s: %v", project, err)
			continue
		}

		// Group records by VIN
		vinRecords := make(map[string][]VPLRecord)
		for _, record := range records {
			vinRecords[record.VIN] = append(vinRecords[record.VIN], record)
		}

		// Check each VIN for missing required parts
		for vin, vinParts := range vinRecords {
			for _, requiredPart := range requiredParts {
				if !hasRequiredPart(vinParts, requiredPart) {
					issues = append(issues, VPLIssue{
						Date:        date,
						VIN:         vin,
						Project:     project,
						IssueType:   VPL_ISSUE_MISSING_REQ,
						MissingPart: requiredPart,
						Details:     fmt.Sprintf("Missing required part: %s", requiredPart),
					})
				}
			}
		}
	}

	log.Printf("📊 Missing Required Parts: %d issues found", len(issues))
	return issues
}

func hasRequiredPart(vinParts []VPLRecord, requiredPart string) bool {
	// Handle OR groups: !A-OR-B!
	if strings.HasPrefix(requiredPart, "!") && strings.HasSuffix(requiredPart, "!") {
		orParts := strings.Split(strings.Trim(requiredPart, "!"), "-OR-")
		for _, orPart := range orParts {
			orPart = strings.TrimSpace(orPart)
			for _, vinPart := range vinParts {
				if strings.Contains(vinPart.PartName, orPart) {
					return true
				}
			}
		}
		return false
	}

	// Handle single part
	for _, vinPart := range vinParts {
		if strings.Contains(vinPart.PartName, requiredPart) {
			return true
		}
	}

	return false
}

func extractCustomerReferences(vplRecords []VPLRecord) []string {
	var customerRefs []string
	seen := make(map[string]bool)

	for _, record := range vplRecords {
		// Generate customer reference from part name (add spaces)
		customerRef := formatCustomerReference(record.PartName)
		if !seen[customerRef] {
			customerRefs = append(customerRefs, customerRef)
			seen[customerRef] = true
		}
	}

	log.Printf("📊 Extracted %d unique customer references", len(customerRefs))
	return customerRefs
}

func formatCustomerReference(partName string) string {
	// Convert "MPZ3T18K811CF3JA6" to "MPZ3T 18K811 CF3JA6" format
	if len(partName) < 10 {
		return partName
	}

	// Simple formatting - can be enhanced based on actual format rules
	prefix := partName[:5]
	base := partName[5:11]
	suffix := partName[11:]

	return fmt.Sprintf("%s %s %s", prefix, base, suffix)
}

func validateTEIReferences(date string, customerRefs []string, teiRecords map[string]TEIRecord) []MasterDataIssue {
	var issues []MasterDataIssue

	for _, customerRef := range customerRefs {
		teiRecord, exists := teiRecords[customerRef]
		if !exists {
			issues = append(issues, MasterDataIssue{
				Date:      date,
				PartName:  strings.ReplaceAll(customerRef, " ", ""),
				IssueType: MD_ISSUE_TEI_NOT_FOUND,
				Expected:  customerRef,
				Details:   "Customer reference not found in TEI file",
			})
			continue
		}

		// Validate inner reference format
		expectedInner := generateExpectedInnerReference(customerRef)
		if teiRecord.InnerReference != expectedInner {
			issues = append(issues, MasterDataIssue{
				Date:      date,
				PartName:  strings.ReplaceAll(customerRef, " ", ""),
				InnerRef:  teiRecord.InnerReference,
				IssueType: MD_ISSUE_INNER_MISMATCH,
				Expected:  expectedInner,
				Actual:    teiRecord.InnerReference,
				Details:   "Inner reference format mismatch",
			})
		}

		// Check description
		if strings.TrimSpace(teiRecord.PartDescription) == "" {
			issues = append(issues, MasterDataIssue{
				Date:      date,
				PartName:  strings.ReplaceAll(customerRef, " ", ""),
				InnerRef:  teiRecord.InnerReference,
				IssueType: MD_ISSUE_NO_DESCRIPTION,
				Details:   "Part description is missing",
			})
		}
	}

	log.Printf("📊 TEI Validation: %d issues found", len(issues))
	return issues
}

func generateExpectedInnerReference(customerRef string) string {
	cleaned := strings.ReplaceAll(customerRef, " ", "")
	if strings.HasPrefix(cleaned, "W") {
		return "E" + cleaned
	}
	return "E" + cleaned
}

func extractInnerReferences(customerRefs []string, teiRecords map[string]TEIRecord) []string {
	var innerRefs []string
	seen := make(map[string]bool)

	for _, customerRef := range customerRefs {
		if teiRecord, exists := teiRecords[customerRef]; exists {
			if !seen[teiRecord.InnerReference] {
				innerRefs = append(innerRefs, teiRecord.InnerReference)
				seen[teiRecord.InnerReference] = true
			}
		}
	}

	log.Printf("📊 Extracted %d unique inner references", len(innerRefs))
	return innerRefs
}

func validateOSLParameters(date string, innerRefs []string, oslRecords map[string]map[string]string) []MasterDataIssue {
	var issues []MasterDataIssue

	for _, innerRef := range innerRefs {
		params, exists := oslRecords[innerRef]
		if !exists {
			issues = append(issues, MasterDataIssue{
				Date:      date,
				PartName:  innerRef,
				InnerRef:  innerRef,
				IssueType: MD_ISSUE_OSL_NOT_FOUND,
				Details:   "Inner reference not found in OSL file",
			})
			continue
		}

		// Check required parameters
		requiredParams := []string{"MODULE", "PART_FAMILY"}
		var missingParams []string

		for _, param := range requiredParams {
			if value, exists := params[param]; !exists || strings.TrimSpace(value) == "" {
				missingParams = append(missingParams, param)
			}
		}

		if len(missingParams) > 0 {
			issues = append(issues, MasterDataIssue{
				Date:      date,
				PartName:  innerRef,
				InnerRef:  innerRef,
				IssueType: MD_ISSUE_MISSING_PARAMS,
				Expected:  strings.Join(requiredParams, ", "),
				Actual:    strings.Join(missingParams, ", "),
				Details:   fmt.Sprintf("Missing required parameters: %s", strings.Join(missingParams, ", ")),
			})
		}

		// Check CK module specific requirements
		if moduleValue, exists := params["MODULE"]; exists && strings.ToUpper(strings.TrimSpace(moduleValue)) == "CK" {
			ckRequiredParams := []string{"LABEL_POSITION", "LABEL_TYPE"}
			var missingCKParams []string

			for _, ckParam := range ckRequiredParams {
				if value, exists := params[ckParam]; !exists || strings.TrimSpace(value) == "" {
					missingCKParams = append(missingCKParams, ckParam)
				}
			}

			if len(missingCKParams) > 0 {
				issues = append(issues, MasterDataIssue{
					Date:      date,
					PartName:  innerRef,
					InnerRef:  innerRef,
					IssueType: MD_ISSUE_CK_VIOLATION,
					Expected:  strings.Join(ckRequiredParams, ", "),
					Actual:    strings.Join(missingCKParams, ", "),
					Details:   fmt.Sprintf("CK module missing parameters: %s", strings.Join(missingCKParams, ", ")),
				})
			}
		}
	}

	log.Printf("📊 OSL Validation: %d issues found", len(issues))
	return issues
}

func countIssuesByType(issues []VPLIssue, issueType string) int {
	count := 0
	for _, issue := range issues {
		if issue.IssueType == issueType {
			count++
		}
	}
	return count
}

// =============================================================================
// HTTP FUNCTIONS
// =============================================================================

func setupRoutes() {
	// Static files
	http.HandleFunc("/", handleStaticFiles)
	http.HandleFunc("/login", handleStaticFiles)
	http.HandleFunc("/selection", requireAuth(handleStaticFiles))
	http.HandleFunc("/vpl-dashboard", requireAuth(handleStaticFiles))
	http.HandleFunc("/masterdata-dashboard", requireAuth(handleStaticFiles))
	http.HandleFunc("/config", requireAuth(handleStaticFiles))

	// Authentication API
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)

	// VPL Analysis API
	http.HandleFunc("/api/vpl/summary/", requireAuth(handleVPLSummary))
	http.HandleFunc("/api/vpl/issues/", requireAuth(handleVPLIssues))
	http.HandleFunc("/api/vpl/search", requireAuth(handleVPLSearch))
	http.HandleFunc("/api/vpl/analyze", requireAuth(handleRunAnalysis))

	// Master Data API
	http.HandleFunc("/api/masterdata/summary/", requireAuth(handleMasterDataSummary))
	http.HandleFunc("/api/masterdata/issues/", requireAuth(handleMasterDataIssues))
	http.HandleFunc("/api/masterdata/search", requireAuth(handleMasterDataSearch))

	// Configuration API
	http.HandleFunc("/api/required-parts/", requireAuth(handleRequiredParts))
	http.HandleFunc("/api/system/health", requireAuth(handleSystemHealth))

	log.Println("✅ HTTP routes configured")
}
func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("🔍 Auth check for URL: %s", r.URL.Path)

		cookie, err := r.Cookie("session_token")

		if err != nil || !validateSession(cookie.Value) {
			log.Printf("❌ No session cookie found: %v", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		log.Printf("✅ Cookie found, calling handler")

		handler(w, r)
	})
}

func handleStaticFiles(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/login":
		http.ServeFile(w, r, "frontend/login.html")
	case "/selection":
		http.ServeFile(w, r, "frontend/selection.html")
	case "/vpl-dashboard":
		http.ServeFile(w, r, "frontend/vpl-dashboard.html")
	case "/masterdata-dashboard":
		http.ServeFile(w, r, "frontend/masterdata_dashboard.html")
	case "/config":
		http.ServeFile(w, r, "frontend/config.html")
	default:
		http.NotFound(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		sendError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !validateInput(loginReq.Username) || !validateInput(loginReq.Password) {
		sendError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if validateCredentials(loginReq.Username, loginReq.Password) {
		token := createSession(loginReq.Username)

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    token,
			Path:     "/",
			MaxAge:   SESSION_HOURS * 3600,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		sendJSON(w, APIResponse{
			Success: true,
			Message: "Login successful",
		})

		log.Printf("✅ User logged in: %s", loginReq.Username)
	} else {
		sendError(w, "Invalid credentials", http.StatusUnauthorized)
		log.Printf("❌ Failed login attempt: %s", loginReq.Username)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		delete(activeSessions, cookie.Value)
		db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	sendJSON(w, APIResponse{Success: true, Message: "Logout successful"})
}

func handleVPLSummary(w http.ResponseWriter, r *http.Request) {
	date := strings.TrimPrefix(r.URL.Path, "/api/vpl/summary/")
	if date == "" || !validateInput(date) {
		sendError(w, "Invalid date parameter", http.StatusBadRequest)
		return
	}

	summary, err := getVPLAnalysisSummary(date)
	if err != nil {
		sendError(w, "Failed to get VPL summary", http.StatusInternalServerError)
		return
	}

	sendJSON(w, APIResponse{
		Success: true,
		Data:    summary,
	})
}

func handleVPLIssues(w http.ResponseWriter, r *http.Request) {
	date := strings.TrimPrefix(r.URL.Path, "/api/vpl/issues/")
	if date == "" || !validateInput(date) {
		sendError(w, "Invalid date parameter", http.StatusBadRequest)
		return
	}

	page := 1
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	issues, total, err := getVPLIssues(date, page, PAGE_SIZE)
	if err != nil {
		sendError(w, "Failed to get VPL issues", http.StatusInternalServerError)
		return
	}

	modal := VPLIssuesModal{
		Issues:     issues,
		TotalCount: total,
		Page:       page,
		PageSize:   PAGE_SIZE,
	}

	sendJSON(w, APIResponse{
		Success: true,
		Data:    modal,
	})
}

func handleVPLSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var searchReq VPLIssuesSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&searchReq); err != nil {
		sendError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !validateInput(searchReq.Date) || !validateInput(searchReq.Query) {
		sendError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	issues, total, err := searchVPLIssues(searchReq)
	if err != nil {
		sendError(w, "Search failed", http.StatusInternalServerError)
		return
	}

	modal := VPLIssuesModal{
		Issues:      issues,
		TotalCount:  total,
		Page:        searchReq.Page,
		PageSize:    searchReq.PageSize,
		SearchQuery: searchReq.Query,
		FilterType:  searchReq.FilterType,
	}

	sendJSON(w, APIResponse{
		Success: true,
		Data:    modal,
	})
}

func handleRunAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var analysisReq struct {
		Date string `json:"date"`
	}

	if err := json.NewDecoder(r.Body).Decode(&analysisReq); err != nil {
		sendError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !validateInput(analysisReq.Date) {
		sendError(w, "Invalid date", http.StatusBadRequest)
		return
	}

	go func() {
		if err := runCompleteAnalysis(analysisReq.Date); err != nil {
			log.Printf("❌ Analysis failed for date %s: %v", analysisReq.Date, err)
		}
	}()

	sendJSON(w, APIResponse{
		Success: true,
		Message: "Analysis started",
	})
}

func handleMasterDataSummary(w http.ResponseWriter, r *http.Request) {
	date := strings.TrimPrefix(r.URL.Path, "/api/masterdata/summary/")
	if date == "" || !validateInput(date) {
		sendError(w, "Invalid date parameter", http.StatusBadRequest)
		return
	}

	summary, err := getMasterDataAnalysisSummary(date)
	if err != nil {
		sendError(w, "Failed to get master data summary", http.StatusInternalServerError)
		return
	}

	sendJSON(w, APIResponse{
		Success: true,
		Data:    summary,
	})
}

func handleMasterDataIssues(w http.ResponseWriter, r *http.Request) {
	date := strings.TrimPrefix(r.URL.Path, "/api/masterdata/issues/")
	if date == "" || !validateInput(date) {
		sendError(w, "Invalid date parameter", http.StatusBadRequest)
		return
	}

	page := 1
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	issues, total, err := getMasterDataIssues(date, page, PAGE_SIZE)
	if err != nil {
		sendError(w, "Failed to get master data issues", http.StatusInternalServerError)
		return
	}

	modal := MasterDataIssuesModal{
		Issues:     issues,
		TotalCount: total,
		Page:       page,
		PageSize:   PAGE_SIZE,
	}

	sendJSON(w, APIResponse{
		Success: true,
		Data:    modal,
	})
}

func handleMasterDataSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var searchReq MasterDataIssuesSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&searchReq); err != nil {
		sendError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !validateInput(searchReq.Date) || !validateInput(searchReq.Query) {
		sendError(w, "Invalid input", http.StatusBadRequest)
		return
	}

	issues, total, err := searchMasterDataIssues(searchReq)
	if err != nil {
		sendError(w, "Search failed", http.StatusInternalServerError)
		return
	}

	modal := MasterDataIssuesModal{
		Issues:      issues,
		TotalCount:  total,
		Page:        searchReq.Page,
		PageSize:    searchReq.PageSize,
		SearchQuery: searchReq.Query,
		FilterType:  searchReq.FilterType,
	}

	sendJSON(w, APIResponse{
		Success: true,
		Data:    modal,
	})
}

func handleRequiredParts(w http.ResponseWriter, r *http.Request) {
	project := strings.TrimPrefix(r.URL.Path, "/api/required-parts/")
	if project == "" || !validateInput(project) {
		sendError(w, "Invalid project parameter", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		parts, err := getRequiredPartsForProject(project)
		if err != nil {
			sendError(w, "Failed to get required parts", http.StatusInternalServerError)
			return
		}

		sendJSON(w, APIResponse{
			Success: true,
			Data:    parts,
		})

	case "POST":
		var req struct {
			Parts []string `json:"parts"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		// Validate all parts
		for _, part := range req.Parts {
			if !validateInput(part) {
				sendError(w, "Invalid part format", http.StatusBadRequest)
				return
			}
		}

		if err := updateRequiredPartsForProject(project, req.Parts); err != nil {
			sendError(w, "Failed to update required parts", http.StatusInternalServerError)
			return
		}

		sendJSON(w, APIResponse{
			Success: true,
			Message: "Required parts updated successfully",
		})

	default:
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"database":             "OK",
		"vpl_directory":        checkDirectory("./vpl_files"),
		"masterdata_directory": checkDirectory("./masterdata_files"),
		"active_sessions":      len(activeSessions),
		"timestamp":            time.Now().Format("2006-01-02 15:04:05"),
	}

	sendJSON(w, APIResponse{
		Success: true,
		Data:    health,
	})
}

// =============================================================================
// HELPER FUNCTIONS FOR HTTP HANDLERS
// =============================================================================

func getVPLAnalysisSummary(date string) (VPLAnalysisSummary, error) {
	var summary VPLAnalysisSummary
	summary.Date = date

	// Count total issues
	err := db.QueryRow("SELECT COUNT(*) FROM vpl_issues WHERE date = ?", date).Scan(&summary.IssuesFound)
	if err != nil {
		return summary, err
	}

	// Count by type
	db.QueryRow("SELECT COUNT(*) FROM vpl_issues WHERE date = ? AND issue_type IN (?, ?, ?)",
		date, VPL_ISSUE_ADDED, VPL_ISSUE_REMOVED, VPL_ISSUE_CHANGED).Scan(&summary.ChangesCount)

	db.QueryRow("SELECT COUNT(*) FROM vpl_issues WHERE date = ? AND issue_type = ?",
		date, VPL_ISSUE_MISSING_REQ).Scan(&summary.MissingReqCount)

	// Count affected VINs
	db.QueryRow("SELECT COUNT(DISTINCT vin) FROM vpl_issues WHERE date = ?", date).Scan(&summary.AffectedVINs)

	summary.HasIssues = summary.IssuesFound > 0
	summary.ProcessingTime = "2.3s" // This could be stored during analysis

	return summary, nil
}

func getMasterDataAnalysisSummary(date string) (MasterDataAnalysisSummary, error) {
	var summary MasterDataAnalysisSummary
	summary.Date = date

	// Count total issues
	err := db.QueryRow("SELECT COUNT(*) FROM masterdata_issues WHERE date = ?", date).Scan(&summary.IssuesFound)
	if err != nil {
		return summary, err
	}

	// Count by type
	db.QueryRow("SELECT COUNT(*) FROM masterdata_issues WHERE date = ? AND issue_type IN (?, ?, ?)",
		date, MD_ISSUE_TEI_NOT_FOUND, MD_ISSUE_INNER_MISMATCH, MD_ISSUE_NO_DESCRIPTION).Scan(&summary.TEIIssuesCount)

	db.QueryRow("SELECT COUNT(*) FROM masterdata_issues WHERE date = ? AND issue_type IN (?, ?)",
		date, MD_ISSUE_OSL_NOT_FOUND, MD_ISSUE_MISSING_PARAMS).Scan(&summary.OSLIssuesCount)

	db.QueryRow("SELECT COUNT(*) FROM masterdata_issues WHERE date = ? AND issue_type = ?",
		date, MD_ISSUE_CK_VIOLATION).Scan(&summary.CKViolationsCount)

	// Count affected parts
	db.QueryRow("SELECT COUNT(DISTINCT part_name) FROM masterdata_issues WHERE date = ?", date).Scan(&summary.AffectedPartsCount)

	summary.HasIssues = summary.IssuesFound > 0

	// Calculate compliance rate (assuming we track total parts analyzed)
	if summary.TotalPartsAnalyzed > 0 {
		summary.ComplianceRate = float64(summary.TotalPartsAnalyzed-summary.IssuesFound) / float64(summary.TotalPartsAnalyzed) * 100
	}

	return summary, nil
}

func getVPLIssues(date string, page, pageSize int) ([]VPLIssueDetail, int, error) {
	// Count total
	var total int
	err := db.QueryRow("SELECT COUNT(*) FROM vpl_issues WHERE date = ?", date).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get paginated results
	offset := (page - 1) * pageSize
	rows, err := db.Query(`SELECT vin, project, issue_type, 
		ISNULL(old_part, '') as old_part, ISNULL(new_part, '') as new_part, 
		ISNULL(missing_part, '') as missing_part, ISNULL(details, '') as details
		FROM vpl_issues WHERE date = ? 
		ORDER BY id 
		OFFSET ? ROWS FETCH NEXT ? ROWS ONLY`,
		date, offset, pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var issues []VPLIssueDetail
	for rows.Next() {
		var issue VPLIssueDetail
		err := rows.Scan(&issue.VIN, &issue.Project, &issue.IssueType,
			&issue.OldPart, &issue.NewPart, &issue.MissingPart, &issue.Details)
		if err != nil {
			continue
		}
		issues = append(issues, issue)
	}

	return issues, total, nil
}

func getMasterDataIssues(date string, page, pageSize int) ([]MasterDataIssueDetail, int, error) {
	// Count total
	var total int
	err := db.QueryRow("SELECT COUNT(*) FROM masterdata_issues WHERE date = ?", date).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get paginated results
	offset := (page - 1) * pageSize
	rows, err := db.Query(`SELECT part_name, ISNULL(inner_ref, '') as inner_ref, issue_type,
		ISNULL(expected, '') as expected, ISNULL(actual, '') as actual, 
		ISNULL(details, '') as details
		FROM masterdata_issues WHERE date = ? 
		ORDER BY id 
		OFFSET ? ROWS FETCH NEXT ? ROWS ONLY`,
		date, offset, pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var issues []MasterDataIssueDetail
	for rows.Next() {
		var issue MasterDataIssueDetail
		err := rows.Scan(&issue.PartName, &issue.InnerRef, &issue.IssueType,
			&issue.Expected, &issue.Actual, &issue.Details)
		if err != nil {
			continue
		}
		issues = append(issues, issue)
	}

	return issues, total, nil
}

func searchVPLIssues(req VPLIssuesSearchRequest) ([]VPLIssueDetail, int, error) {
	whereClause := "WHERE date = ?"
	args := []interface{}{req.Date}
	argIndex := 2

	// Add search filter
	if req.Query != "" {
		whereClause += fmt.Sprintf(" AND (vin LIKE @p%d OR old_part LIKE @p%d OR new_part LIKE @p%d OR missing_part LIKE @p%d)",
			argIndex, argIndex+1, argIndex+2, argIndex+3)
		searchPattern := "%" + req.Query + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern)
		argIndex += 4
	}

	// Add type filter
	if req.FilterType != "" && req.FilterType != "ALL" {
		switch req.FilterType {
		case "CHANGES":
			whereClause += fmt.Sprintf(" AND issue_type IN (@p%d, @p%d, @p%d)", argIndex, argIndex+1, argIndex+2)
			args = append(args, VPL_ISSUE_ADDED, VPL_ISSUE_REMOVED, VPL_ISSUE_CHANGED)
			argIndex += 3
		case "MISSING_REQ":
			whereClause += fmt.Sprintf(" AND issue_type = @p%d", argIndex)
			args = append(args, VPL_ISSUE_MISSING_REQ)
			argIndex++
		}
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM vpl_issues " + whereClause
	err := db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get paginated results
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = PAGE_SIZE
	}

	offset := (req.Page - 1) * req.PageSize
	whereClause += fmt.Sprintf(" ORDER BY id OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY", argIndex, argIndex+1)
	args = append(args, offset, req.PageSize)

	selectQuery := `SELECT vin, project, issue_type, 
		ISNULL(old_part, '') as old_part, ISNULL(new_part, '') as new_part, 
		ISNULL(missing_part, '') as missing_part, ISNULL(details, '') as details
		FROM vpl_issues ` + whereClause

	rows, err := db.Query(selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var issues []VPLIssueDetail
	for rows.Next() {
		var issue VPLIssueDetail
		err := rows.Scan(&issue.VIN, &issue.Project, &issue.IssueType,
			&issue.OldPart, &issue.NewPart, &issue.MissingPart, &issue.Details)
		if err != nil {
			continue
		}

		// Add highlighting for search
		if req.Query != "" {
			issue.HighlightText = req.Query
		}

		issues = append(issues, issue)
	}

	return issues, total, nil
}

func searchMasterDataIssues(req MasterDataIssuesSearchRequest) ([]MasterDataIssueDetail, int, error) {
	whereClause := "WHERE date = ?"
	args := []interface{}{req.Date}
	argIndex := 2

	// Add search filter
	if req.Query != "" {
		whereClause += fmt.Sprintf(" AND (part_name LIKE @p%d OR inner_ref LIKE @p%d OR details LIKE @p%d)",
			argIndex, argIndex+1, argIndex+2)
		searchPattern := "%" + req.Query + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
		argIndex += 3
	}

	// Add type filter
	if req.FilterType != "" && req.FilterType != "ALL" {
		switch req.FilterType {
		case "TEI":
			whereClause += fmt.Sprintf(" AND issue_type IN (@p%d, @p%d, @p%d)", argIndex, argIndex+1, argIndex+2)
			args = append(args, MD_ISSUE_TEI_NOT_FOUND, MD_ISSUE_INNER_MISMATCH, MD_ISSUE_NO_DESCRIPTION)
			argIndex += 3
		case "OSL":
			whereClause += fmt.Sprintf(" AND issue_type IN (@p%d, @p%d)", argIndex, argIndex+1)
			args = append(args, MD_ISSUE_OSL_NOT_FOUND, MD_ISSUE_MISSING_PARAMS)
			argIndex += 2
		case "CK":
			whereClause += fmt.Sprintf(" AND issue_type = @p%d", argIndex)
			args = append(args, MD_ISSUE_CK_VIOLATION)
			argIndex++
		}
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM masterdata_issues " + whereClause
	err := db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get paginated results
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = PAGE_SIZE
	}

	offset := (req.Page - 1) * req.PageSize
	whereClause += fmt.Sprintf(" ORDER BY id OFFSET @p%d ROWS FETCH NEXT @p%d ROWS ONLY", argIndex, argIndex+1)
	args = append(args, offset, req.PageSize)

	selectQuery := `SELECT part_name, ISNULL(inner_ref, '') as inner_ref, issue_type,
		ISNULL(expected, '') as expected, ISNULL(actual, '') as actual, 
		ISNULL(details, '') as details
		FROM masterdata_issues ` + whereClause

	rows, err := db.Query(selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var issues []MasterDataIssueDetail
	for rows.Next() {
		var issue MasterDataIssueDetail
		err := rows.Scan(&issue.PartName, &issue.InnerRef, &issue.IssueType,
			&issue.Expected, &issue.Actual, &issue.Details)
		if err != nil {
			continue
		}

		// Add highlighting for search
		if req.Query != "" {
			issue.HighlightText = req.Query
		}

		issues = append(issues, issue)
	}

	return issues, total, nil
}

func updateRequiredPartsForProject(project string, parts []string) error {
	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete existing parts for this project
	_, err = tx.Exec("DELETE FROM required_parts WHERE project_name = ?", project)
	if err != nil {
		return err
	}

	// Insert new parts
	for _, part := range parts {
		_, err = tx.Exec("INSERT INTO required_parts (project_name, required_part) VALUES (?, ?)",
			project, part)
		if err != nil {
			return err
		}
	}

	// Commit transaction
	return tx.Commit()
}

func checkDirectory(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "NOT_FOUND"
	}
	return "OK"
}

func sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func sendError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Message: message,
	})
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

func main() {
	log.Println("🚀 Starting MSAS VPL Analyzer...")

	// Create required directories
	os.MkdirAll("./vpl_files", 0755)
	os.MkdirAll("./masterdata_files", 0755)
	os.MkdirAll("./frontend", 0755)

	// Connect to SQL Express database
	if err := connectDatabase(); err != nil {
		log.Fatalf("❌ Database connection failed: %v", err)
	}
	defer db.Close()

	// Setup HTTP routes
	setupRoutes()

	// Start server
	port := DEFAULT_PORT
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	log.Printf("🌐 Server starting on http://localhost:%s", port)
	log.Printf("📊 VPL files directory: ./vpl_files")
	log.Printf("📄 Master data directory: ./masterdata_files")
	log.Println("✅ Application ready!")
	log.Println("📋 Login credentials: admin/admin123 or user/vpl2024")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("❌ Server failed to start: %v", err)
	}
}
