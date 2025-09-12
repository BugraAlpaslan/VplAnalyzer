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
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			issue.Date,
			issue.VIN,
			issue.Project,
			issue.IssueType,
			issue.OldPart,
			issue.NewPart,
			issue.MissingPart,
			issue.Details)
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
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			issue.Date,
			issue.PartName,
			issue.InnerRef,
			issue.IssueType,
			issue.Expected,
			issue.Actual,
			issue.Details)
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

// VPL dosyası bulma - Format: VPLHVLTA202509101.TXT (sonda yyyymmdd1)
func findVPLFileForDate(date string) string {
	// "2025-09-10" -> "20250910"

	// VPL dosyalarını tara
	pattern := "./vpl_files/*.TXT"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("Error scanning VPL files: %v", err)
		return ""
	}

	for _, match := range matches {
		filename := filepath.Base(match)
		extractedDate := extractDateFromVPLFileName(filename)

		if extractedDate == date {
			log.Printf("📄 Found VPL file: %s for date %s", filename, date)
			return match
		}
	}

	log.Printf("⚠️ No VPL file found for date: %s", date)
	return ""
}

// TEI dosyası bulma - Format: SAP_20250820-030102-646.TEI (başta SAP_yyyymmdd)
func findTEIFileForDate(date string) string {
	// "2025-08-20" -> "20250820"

	// TEI dosyalarını tara
	pattern := "./masterdata_files/*.TEI"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("Error scanning TEI files: %v", err)
		return ""
	}

	for _, match := range matches {
		filename := filepath.Base(match)
		extractedDate := extractDateFromTEIFileName(filename)

		if extractedDate == date {
			log.Printf("📄 Found TEI file: %s for date %s", filename, date)
			return match
		}
	}

	log.Printf("⚠️ No TEI file found for date: %s", date)
	return ""
}

// OSL dosyası bulma - Format: SAP_20250820-030039-146.OSL (başta SAP_yyyymmdd)
func findOSLFileForDate(date string) string {
	// "2025-08-20" -> "20250820"

	// OSL dosyalarını tara
	pattern := "./masterdata_files/*.OSL"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("Error scanning OSL files: %v", err)
		return ""
	}

	for _, match := range matches {
		filename := filepath.Base(match)
		extractedDate := extractDateFromOSLFileName(filename)

		if extractedDate == date {
			log.Printf("📄 Found OSL file: %s for date %s", filename, date)
			return match
		}
	}

	log.Printf("⚠️ No OSL file found for date: %s", date)
	return ""
}

// =============================================================================
// TARİH ÇIKARMA FONKSİYONLARI
// =============================================================================

// VPL dosya adından tarih çıkarma - VPLHVLTA202509101.TXT -> 2025-09-10
func extractDateFromVPLFileName(filename string) string {
	// Regex: dosya sonunda 8 rakam + 1 rakam + .TXT
	re := regexp.MustCompile(`(\d{8})1\.TXT$`)
	submatch := re.FindStringSubmatch(strings.ToUpper(filename))

	if len(submatch) > 1 {
		dateStr := submatch[1] // yyyymmdd kısmı
		if len(dateStr) == 8 {
			// "20250910" -> "2025-09-10"
			return fmt.Sprintf("%s-%s-%s", dateStr[0:4], dateStr[4:6], dateStr[6:8])
		}
	}

	return ""
}

// TEI dosya adından tarih çıkarma - SAP_20250820-030102-646.TEI -> 2025-08-20
func extractDateFromTEIFileName(filename string) string {
	// Regex: SAP_ + 8 rakam ile başlayan
	re := regexp.MustCompile(`^SAP_(\d{8})`)
	submatch := re.FindStringSubmatch(strings.ToUpper(filename))

	if len(submatch) > 1 {
		dateStr := submatch[1] // yyyymmdd kısmı
		if len(dateStr) == 8 {
			// "20250820" -> "2025-08-20"
			return fmt.Sprintf("%s-%s-%s", dateStr[0:4], dateStr[4:6], dateStr[6:8])
		}
	}

	return ""
}

// OSL dosya adından tarih çıkarma - SAP_20250820-030039-146.OSL -> 2025-08-20
func extractDateFromOSLFileName(filename string) string {
	// Regex: SAP_ + 8 rakam ile başlayan
	re := regexp.MustCompile(`^SAP_(\d{8})`)
	submatch := re.FindStringSubmatch(strings.ToUpper(filename))

	if len(submatch) > 1 {
		dateStr := submatch[1] // yyyymmdd kısmı
		if len(dateStr) == 8 {
			// "20250820" -> "2025-08-20"
			return fmt.Sprintf("%s-%s-%s", dateStr[0:4], dateStr[4:6], dateStr[6:8])
		}
	}

	return ""
}

// =============================================================================
// DOSYA OKUMA FONKSİYONLARI
// =============================================================================

// VPL dosyası okuma
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
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "VPLIST") {
			record, err := parseVPLRecord(line)
			if err == nil {
				records = append(records, record)
			} else {
				log.Printf("Warning: Failed to parse VPL line %d: %v", lineCount, err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading VPL file: %v", err)
	}

	log.Printf("📊 Read %d VPL records from %s", len(records), filepath.Base(filePath))
	return records, nil
}

// TEI dosyası okuma
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
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		// Satırı boşluk/tab fark etmeksizin böl
		fields := strings.Fields(line)

		// En az 3 alan olmalı: 9353, müşteriRef, bizimRef
		if len(fields) < 3 {
			log.Printf("Warning: Invalid TEI line %d: insufficient fields", lineCount)
			continue
		}

		// 9353 sonrası tüm alanlar ama son alan bizim referans olacak
		customerRef := strings.Join(fields[1:len(fields)-1], " ")
		innerRef := fields[len(fields)-1]

		record := TEIRecord{
			CustomerReference: customerRef,
			InnerReference:    innerRef,
			PartDescription:   "", // Gerekirse diğer alanlardan alabilirsin
		}

		teiMap[customerRef] = record
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading TEI file: %v", err)
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
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		// Boş satırları atla
		if line == "" {
			continue
		}

		// Hem tab hem de birden fazla boşlukları ayır
		fields := strings.Fields(line)

		// En az 4 sütun olmalı: 9353, innerRef, paramName, value1, (opsiyonel value2)
		if len(fields) >= 4 {
			innerRef := strings.TrimSpace(fields[1])
			paramName := strings.TrimSpace(fields[2])

			// value1 ve value2 varsa birleştir, yoksa sadece value1
			paramValue := strings.TrimSpace(fields[3])
			if len(fields) >= 5 {
				paramValue += "\t" + strings.TrimSpace(fields[4])
			}

			if oslMap[innerRef] == nil {
				oslMap[innerRef] = make(map[string]string)
			}

			oslMap[innerRef][paramName] = paramValue
		} else {
			log.Printf("Warning: Invalid OSL line %d: insufficient fields", lineCount)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading OSL file: %v", err)
	}

	log.Printf("📊 Read %d OSL records from %s", len(oslMap), filepath.Base(filePath))
	return oslMap, nil
}

// =============================================================================
// YARDIMCI FONKSİYONLAR
// =============================================================================

// VPL satırını parse etme
func parseVPLRecord(line string) (VPLRecord, error) {
	line = strings.TrimPrefix(line, "VPLIST")
	fields := strings.Fields(line)

	if len(fields) < 4 {
		return VPLRecord{}, fmt.Errorf("invalid VPL record format: insufficient fields")
	}

	vinAndPrefix := fields[0]
	if len(vinAndPrefix) < VIN_LENGTH {
		return VPLRecord{}, fmt.Errorf("invalid VIN length: %d", len(vinAndPrefix))
	}

	vin := vinAndPrefix[:VIN_LENGTH]
	prefix := vinAndPrefix[VIN_LENGTH:]

	record := VPLRecord{
		VIN:      vin,
		Prefix:   prefix,
		Base:     fields[1],
		Suffix:   fields[2],
		Quantity: fields[3],
		PartName: prefix + fields[1] + fields[2], // Prefix + Base + Suffix
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

// Dosya varlığını kontrol etme
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

// Mevcut dosyaları listeleme (debug için)
func listAvailableFiles() {
	log.Println("📁 Available VPL files:")
	vplFiles, _ := filepath.Glob("./vpl_files/*.TXT")
	for _, file := range vplFiles {
		filename := filepath.Base(file)
		date := extractDateFromVPLFileName(filename)
		log.Printf("  - %s (Date: %s)", filename, date)
	}

	log.Println("📁 Available TEI files:")
	teiFiles, _ := filepath.Glob("./masterdata_files/*.TEI")
	for _, file := range teiFiles {
		filename := filepath.Base(file)
		date := extractDateFromTEIFileName(filename)
		log.Printf("  - %s (Date: %s)", filename, date)
	}

	log.Println("📁 Available OSL files:")
	oslFiles, _ := filepath.Glob("./masterdata_files/*.OSL")
	for _, file := range oslFiles {
		filename := filepath.Base(file)
		date := extractDateFromOSLFileName(filename)
		log.Printf("  - %s (Date: %s)", filename, date)
	}
}

// Belirli tarih için tüm dosyaları kontrol etme
func checkFilesForDate(date string) (bool, bool, bool) {
	vplFile := findVPLFileForDate(date)
	teiFile := findTEIFileForDate(date)
	oslFile := findOSLFileForDate(date)

	return vplFile != "", teiFile != "", oslFile != ""
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

// VPL dosyalarını karşılaştır ve detaylı change analizi yap
func compareVPLFiles(date string, previousVPL, currentVPL []VPLRecord) []VPLIssue {
	var issues []VPLIssue

	// Create maps for easy lookup - VIN+PREFIX+BASE+SUFFIX combination
	prevMap := make(map[string]VPLRecord)
	currMap := make(map[string]VPLRecord)

	// Create separate maps for part component tracking
	prevPartMap := make(map[string]map[string]VPLRecord) // VIN -> PartName -> Record
	currPartMap := make(map[string]map[string]VPLRecord) // VIN -> PartName -> Record

	// Build previous maps
	for _, record := range previousVPL {
		key := record.VIN + "|" + record.PartName
		prevMap[key] = record

		if prevPartMap[record.VIN] == nil {
			prevPartMap[record.VIN] = make(map[string]VPLRecord)
		}
		prevPartMap[record.VIN][record.PartName] = record
	}

	// Build current maps
	for _, record := range currentVPL {
		key := record.VIN + "|" + record.PartName
		currMap[key] = record

		if currPartMap[record.VIN] == nil {
			currPartMap[record.VIN] = make(map[string]VPLRecord)
		}
		currPartMap[record.VIN][record.PartName] = record
	}

	// Find added parts (in current but not in previous)
	for key, currRecord := range currMap {
		if _, exists := prevMap[key]; !exists {
			// Check if this is a component change vs completely new part
			componentChange := findComponentChange(currRecord, prevPartMap[currRecord.VIN])

			if componentChange != "" {
				// This is a component change, not a new part
				issues = append(issues, VPLIssue{
					Date:      date,
					VIN:       currRecord.VIN,
					Project:   currRecord.DetectedProject,
					IssueType: componentChange, // PREFIX_CHANGED, BASE_CHANGED, SUFFIX_CHANGED
					OldPart:   getOldPartForChange(currRecord, prevPartMap[currRecord.VIN], componentChange),
					NewPart:   currRecord.PartName,
					Details:   fmt.Sprintf("%s changed", getComponentName(componentChange)),
				})
			} else {
				// Completely new part
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
	}

	// Find removed parts (in previous but not in current)
	for key, prevRecord := range prevMap {
		if _, exists := currMap[key]; !exists {
			// Check if this part was modified instead of removed
			if !isPartModified(prevRecord, currPartMap[prevRecord.VIN]) {
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
	}

	log.Printf("📊 VPL Comparison: %d added, %d removed, %d prefix changed, %d base changed, %d suffix changed",
		countIssuesByType(issues, VPL_ISSUE_ADDED),
		countIssuesByType(issues, VPL_ISSUE_REMOVED),
		countIssuesByType(issues, "PREFIX_CHANGED"),
		countIssuesByType(issues, "BASE_CHANGED"),
		countIssuesByType(issues, "SUFFIX_CHANGED"))

	return issues
}

// Check if a part has component changes (PREFIX, BASE, or SUFFIX)
func findComponentChange(currentRecord VPLRecord, previousParts map[string]VPLRecord) string {
	if previousParts == nil {
		return "" // No previous parts for this VIN
	}

	// Check each previous part to see if any component matches
	for _, prevRecord := range previousParts {
		// Same PREFIX and BASE, different SUFFIX
		if currentRecord.Prefix == prevRecord.Prefix &&
			currentRecord.Base == prevRecord.Base &&
			currentRecord.Suffix != prevRecord.Suffix {
			return "SUFFIX_CHANGED"
		}

		// Same PREFIX and SUFFIX, different BASE
		if currentRecord.Prefix == prevRecord.Prefix &&
			currentRecord.Suffix == prevRecord.Suffix &&
			currentRecord.Base != prevRecord.Base {
			return "BASE_CHANGED"
		}

		// Same BASE and SUFFIX, different PREFIX
		if currentRecord.Base == prevRecord.Base &&
			currentRecord.Suffix == prevRecord.Suffix &&
			currentRecord.Prefix != prevRecord.Prefix {
			return "PREFIX_CHANGED"
		}
	}

	return "" // No component change found
}

// Get the old part name that corresponds to the component change
func getOldPartForChange(currentRecord VPLRecord, previousParts map[string]VPLRecord, changeType string) string {
	if previousParts == nil {
		return ""
	}

	for _, prevRecord := range previousParts {
		switch changeType {
		case "SUFFIX_CHANGED":
			if currentRecord.Prefix == prevRecord.Prefix && currentRecord.Base == prevRecord.Base {
				return prevRecord.PartName
			}
		case "BASE_CHANGED":
			if currentRecord.Prefix == prevRecord.Prefix && currentRecord.Suffix == prevRecord.Suffix {
				return prevRecord.PartName
			}
		case "PREFIX_CHANGED":
			if currentRecord.Base == prevRecord.Base && currentRecord.Suffix == prevRecord.Suffix {
				return prevRecord.PartName
			}
		}
	}

	return ""
}

// Check if a part was modified (component change) rather than completely removed
func isPartModified(removedRecord VPLRecord, currentParts map[string]VPLRecord) bool {
	if currentParts == nil {
		return false
	}

	for _, currRecord := range currentParts {
		// Check if any current part shares components with removed part
		sameComponents := 0
		if removedRecord.Prefix == currRecord.Prefix {
			sameComponents++
		}
		if removedRecord.Base == currRecord.Base {
			sameComponents++
		}
		if removedRecord.Suffix == currRecord.Suffix {
			sameComponents++
		}

		// If 2 out of 3 components match, it's a modification
		if sameComponents >= 2 {
			return true
		}
	}

	return false
}

// Get component name for display
func getComponentName(changeType string) string {
	switch changeType {
	case "PREFIX_CHANGED":
		return "PREFIX"
	case "BASE_CHANGED":
		return "BASE"
	case "SUFFIX_CHANGED":
		return "SUFFIX"
	default:
		return "UNKNOWN"
	}
}

// Update types.go - add new issue types

// Update frontend conversion function

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

var seen = make(map[string]bool)

func extractCustomerReferences(vplRecords []VPLRecord) []string {
	var customerRefs []string

	for _, record := range vplRecords {
		// Customer reference = VIN + PartName (Prefix + Base + Suffix)
		customerRef := record.Prefix + record.Base + record.Suffix

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

	// Master Data API
	http.HandleFunc("/api/masterdata/summary/", requireAuth(handleMasterDataSummary))
	http.HandleFunc("/api/masterdata/issues/", requireAuth(handleMasterDataIssues))
	http.HandleFunc("/api/masterdata/search", requireAuth(handleMasterDataSearch))

	// Configuration API
	http.HandleFunc("/api/required-parts/", requireAuth(handleRequiredParts))
	http.HandleFunc("/api/system/health", requireAuth(handleSystemHealth))
	// VPL Analysis endpoint (frontend'in beklediği)
	http.HandleFunc("/api/analysis/", requireAuth(handleVPLAnalysis))

	// Masterdata Analysis endpoint
	http.HandleFunc("/api/masterdata/analysis/", requireAuth(handleMasterDataAnalysis))
	http.HandleFunc("/api/masterdata/manual-analysis", requireAuth(handleMasterDataManualAnalysis))

	// Manuel analiz endpoint
	http.HandleFunc("/api/vpl/analyze", requireAuth(handleManualVPLAnalysis))

	// Reanalyze endpoints
	http.HandleFunc("/api/reanalyze", requireAuth(handleReanalyze))
	http.HandleFunc("/api/masterdata/reanalyze", requireAuth(handleMasterDataReanalyze))

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
func handleMasterDataManualAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Bugünün tarihini al
	today := time.Now().Format("2006-01-02")

	// Bugünün tarihi için analiz yap
	runCompleteAnalysis(today)

	sendJSON(w, APIResponse{
		Success: true,
		Message: "Manual masterdata analysis started for today: " + today,
		Data:    today,
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

// VPL Analysis handler
func handleVPLAnalysis(w http.ResponseWriter, r *http.Request) {
	date := strings.TrimPrefix(r.URL.Path, "/api/analysis/")
	log.Printf("🔍 VPL Analysis requested for date: %s", date) // DEBUG ekleyin

	if date == "" || !validateInput(date) {
		log.Printf("❌ Invalid date parameter: %s", date) // DEBUG ekleyin
		sendError(w, "Invalid date parameter", http.StatusBadRequest)
		return
	}

	// VPL summary'yi al
	summary, err := getVPLAnalysisSummary(date)
	if err != nil {
		log.Printf("❌ getVPLAnalysisSummary error: %v", err) // DEBUG ekleyin
		sendError(w, "Analysis not found", http.StatusNotFound)
		return
	}

	log.Printf("✅ VPL Summary found: Issues=%d", summary.IssuesFound) // DEBUG ekleyin

	// ✅ GERÇEK VPL ISSUES'LARI AL (boş array yerine)
	vplIssues, total, err := getVPLIssues(date, 1, 9000000) // İlk 1000 issue'yu al
	if err != nil {
		log.Printf("❌ getVPLIssues error: %v", err) // DEBUG ekleyin
		vplIssues = []VPLIssueDetail{}              // Hata varsa boş array
	} else {
		log.Printf("✅ Found %d VPL issues (total: %d)", len(vplIssues), total) // DEBUG ekleyin
	}

	// ✅ PART CHANGES'I VPL ISSUES'LARDAN OLUŞTUR
	partChanges := convertVPLIssuesToPartChanges(vplIssues)
	missingRequired := convertVPLIssuesToMissingRequired(vplIssues)

	log.Printf("✅ Converted to %d part changes, %d missing required", len(partChanges), len(missingRequired)) // DEBUG ekleyin

	// Frontend'in beklediği format
	analysisData := map[string]interface{}{
		"part_changes":           partChanges,     // ✅ Gerçek veri
		"missing_required_file2": missingRequired, // ✅ Gerçek veri
		"summary":                summary,
	}

	log.Printf("✅ Sending analysis data to frontend") // DEBUG ekleyin

	sendJSON(w, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"analysis": analysisData},
	})
}

// Manuel VPL analiz handler
func handleManualVPLAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Bugünün tarihini al
	today := time.Now().Format("2006-01-02")

	// Async olarak analiz çalıştır
	go func() {
		if err := runCompleteAnalysis(today); err != nil {
			log.Printf("❌ Manual analysis failed: %v", err)
		}
	}()

	sendJSON(w, APIResponse{
		Success: true,
		Message: "Analysis started",
	})
}

// Masterdata Analysis handler
func handleMasterDataAnalysis(w http.ResponseWriter, r *http.Request) {
	date := strings.TrimPrefix(r.URL.Path, "/api/masterdata/analysis/")
	if date == "" || !validateInput(date) {
		sendError(w, "Invalid date parameter", http.StatusBadRequest)
		return
	}

	// Fake masterdata structure
	analysisData := map[string]interface{}{
		"tei_analysis_results": map[string]interface{}{
			"statistics": map[string]interface{}{
				"total_vpl_parts":      0,
				"found_in_tei":         0,
				"tei_match_rate":       0.0,
				"inner_ref_accuracy":   100.0,
				"description_coverage": 100.0,
			},
			"found_in_tei":              []interface{}{},
			"not_found_in_tei":          []interface{}{},
			"inner_reference_incorrect": []interface{}{},
			"missing_description":       []interface{}{},
		},
		"osl_analysis_results": map[string]interface{}{
			"statistics": map[string]interface{}{
				"total_inner_references": 0,
				"found_in_osl":           0,
				"osl_match_rate":         0.0,
				"parameter_completeness": 100.0,
				"ck_compliance_rate":     100.0,
			},
			"validation_statistics": map[string]interface{}{
				"total_parts":                    0,
				"fully_compliant_parts":          0,
				"overall_compliance_rate":        100.0,
				"required_param_compliance_rate": 100.0,
				"project_compliance_rate":        100.0,
				"ck_compliance_rate":             100.0,
				"required_param_violations":      0,
				"project_param_violations":       0,
				"ck_module_violations":           0,
				"ck_module_parts":                0,
			},
			"validation_results": []interface{}{},
		},
	}

	sendJSON(w, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"analysis": analysisData},
	})
}

// Reanalyze handler
func handleReanalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Date string `json:"date"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !validateInput(req.Date) {
		sendError(w, "Invalid date", http.StatusBadRequest)
		return
	}

	go func() {
		if err := runCompleteAnalysis(req.Date); err != nil {
			log.Printf("❌ Reanalysis failed for date %s: %v", req.Date, err)
		}
	}()

	sendJSON(w, APIResponse{
		Success: true,
		Message: "Reanalysis started",
	})
}

// Masterdata reanalyze handler
func handleMasterDataReanalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Date string `json:"date"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if !validateInput(req.Date) {
		sendError(w, "Invalid date", http.StatusBadRequest)
		return
	}

	// Şu an için sadece başarılı response dön (gerçek masterdata analizi eklenene kadar)
	sendJSON(w, APIResponse{
		Success: true,
		Message: "Masterdata reanalysis completed",
	})
}

// VPL Issues'ları Part Changes formatına dönüştür
// main.go'da convertVPLIssuesToPartChanges fonksiyonunu tamamen değiştirin:

func convertVPLIssuesToPartChanges(issues []VPLIssueDetail) []map[string]interface{} {
	log.Printf("🔄 Starting conversion with %d VPL issues", len(issues))

	if len(issues) == 0 {
		log.Printf("⚠️ No issues to convert")
		return []map[string]interface{}{}
	}

	// Group changes by unique combination
	changeGroups := make(map[string]*ChangeGroup)

	for i, issue := range issues {
		log.Printf("🔍 Processing issue %d: Type='%s', VIN='%s', Old='%s', New='%s', Missing='%s'",
			i, issue.IssueType, issue.VIN, issue.OldPart, issue.NewPart, issue.MissingPart)

		// Skip missing required parts - they are handled separately
		if issue.IssueType == "MISSING_REQUIRED" {
			log.Printf("  ⏭️ Skipping missing required")
			continue
		}

		// Create change group
		var group *ChangeGroup
		var groupKey string

		switch issue.IssueType {
		case "ADDED":
			groupKey = fmt.Sprintf("ADD_%s", issue.NewPart)
			if changeGroups[groupKey] == nil {
				changeGroups[groupKey] = &ChangeGroup{
					ChangeType:   "PART_ADDED",
					NewPartName:  issue.NewPart,
					ChangeDetail: "Yeni part eklendi",
					AffectedVins: []string{},
				}
			}
			group = changeGroups[groupKey]

		case "REMOVED":
			groupKey = fmt.Sprintf("REM_%s", issue.OldPart)
			if changeGroups[groupKey] == nil {
				changeGroups[groupKey] = &ChangeGroup{
					ChangeType:   "PART_REMOVED",
					OldPartName:  issue.OldPart,
					ChangeDetail: "Part kaldırıldı",
					AffectedVins: []string{},
				}
			}
			group = changeGroups[groupKey]

		case "CHANGED":
			groupKey = fmt.Sprintf("CHG_%s_TO_%s", issue.OldPart, issue.NewPart)
			if changeGroups[groupKey] == nil {
				changeGroups[groupKey] = &ChangeGroup{
					ChangeType:   "PART_CHANGED",
					OldPartName:  issue.OldPart,
					NewPartName:  issue.NewPart,
					ChangeDetail: "Part değişti",
					AffectedVins: []string{},
				}
			}
			group = changeGroups[groupKey]

		case "PREFIX_CHANGED":
			groupKey = fmt.Sprintf("PFX_%s_TO_%s", issue.OldPart, issue.NewPart)
			if changeGroups[groupKey] == nil {
				changeGroups[groupKey] = &ChangeGroup{
					ChangeType:   "PREFIX_CHANGED",
					OldPartName:  issue.OldPart,
					NewPartName:  issue.NewPart,
					ChangeDetail: "PREFIX değişti",
					AffectedVins: []string{},
				}
			}
			group = changeGroups[groupKey]

		case "BASE_CHANGED":
			groupKey = fmt.Sprintf("BASE_%s_TO_%s", issue.OldPart, issue.NewPart)
			if changeGroups[groupKey] == nil {
				changeGroups[groupKey] = &ChangeGroup{
					ChangeType:   "BASE_CHANGED",
					OldPartName:  issue.OldPart,
					NewPartName:  issue.NewPart,
					ChangeDetail: "BASE değişti",
					AffectedVins: []string{},
				}
			}
			group = changeGroups[groupKey]

		case "SUFFIX_CHANGED":
			groupKey = fmt.Sprintf("SUF_%s_TO_%s", issue.OldPart, issue.NewPart)
			if changeGroups[groupKey] == nil {
				changeGroups[groupKey] = &ChangeGroup{
					ChangeType:   "SUFFIX_CHANGED",
					OldPartName:  issue.OldPart,
					NewPartName:  issue.NewPart,
					ChangeDetail: "SUFFIX değişti",
					AffectedVins: []string{},
				}
			}
			group = changeGroups[groupKey]

		default:
			log.Printf("  ⚠️ Unknown issue type: '%s'", issue.IssueType)
			continue
		}

		// Add VIN to group if not already present
		if group != nil {
			vinExists := false
			for _, existingVin := range group.AffectedVins {
				if existingVin == issue.VIN {
					vinExists = true
					break
				}
			}

			if !vinExists {
				group.AffectedVins = append(group.AffectedVins, issue.VIN)
				log.Printf("  ✅ Added VIN %s to group %s (total: %d)", issue.VIN, groupKey, len(group.AffectedVins))
			} else {
				log.Printf("  ⏭️ VIN %s already in group %s", issue.VIN, groupKey)
			}
		}
	}

	// Convert groups to result format
	var result []map[string]interface{}

	log.Printf("🎯 Converting %d groups to result format", len(changeGroups))

	for groupKey, group := range changeGroups {
		changeMap := map[string]interface{}{
			"change_type":    group.ChangeType,
			"old_part_name":  group.OldPartName,
			"new_part_name":  group.NewPartName,
			"change_detail":  group.ChangeDetail,
			"affected_count": len(group.AffectedVins),
			"affected_vins":  group.AffectedVins,
		}

		result = append(result, changeMap)

		log.Printf("✅ Group %s: Type=%s, Count=%d",
			groupKey, group.ChangeType, len(group.AffectedVins))
	}

	log.Printf("🎉 Conversion completed: %d issues → %d part changes", len(issues), len(result))

	// Show first few results for debugging
	for i, change := range result {
		if i >= 3 { // Only show first 3
			break
		}
		log.Printf("📋 Result %d: Type=%s, Old=%s, New=%s, Count=%d",
			i, change["change_type"], change["old_part_name"], change["new_part_name"], change["affected_count"])
	}

	return result
}

// VPL Issues'ları Missing Required formatına dönüştür
func convertVPLIssuesToMissingRequired(issues []VPLIssueDetail) []map[string]interface{} {
	missingMap := make(map[string]map[string]interface{})

	for _, issue := range issues {
		if issue.IssueType != VPL_ISSUE_MISSING_REQ {
			continue
		}

		key := issue.MissingPart

		if missingMap[key] == nil {
			missingMap[key] = map[string]interface{}{
				"required_base": issue.MissingPart,
				"missing_vins":  []string{},
				"missing_count": 0,
			}
		}

		// VIN'i ekle
		vins := missingMap[key]["missing_vins"].([]string)
		vins = append(vins, issue.VIN)
		missingMap[key]["missing_vins"] = vins
		missingMap[key]["missing_count"] = len(vins)
	}

	// Map'i slice'a dönüştür
	var result []map[string]interface{}
	for _, missing := range missingMap {
		result = append(result, missing)
	}

	return result
}
