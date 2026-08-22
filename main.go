package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ─── Configuration ──────────────────────────────────────────────────────────

const (
	MaxSpace     = 2048 * 1024 // 2048 KB in bytes (the tenement's entire floor area)
	MaxFiles     = 128         // maximum files per tenant
	SessionTTL   = 30 * 24 * time.Hour
	DataDir      = "data"
	SitesDir     = "data/sites"
	UsersFile    = "data/users.json"
	SessionsFile = "data/sessions.json"
	CookieName   = "ten_session"
	BcryptCost   = 10 // bcrypt work factor
)

var UsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{1,31}$`)

// ─── Data Types ─────────────────────────────────────────────────────────────

type User struct {
	Username     string    `json:"username"`
	PasswordHash []byte    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type FileInfo struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
}

type ViewData struct {
	Title      string
	Username   string
	CSRFToken  string
	Error      string
	Success    string

	// manage page
	Files        []FileInfo
	UsedSize     int64
	UsedFiles    int
	SizePercent  float64
	FilesPercent float64
	MaxSize      int64
	MaxFiles     int

	// edit page
	Filename string
	Content  string
	FileSize int64

	// tenants page
	Tenants     []string
	TenantCount int
}

// ─── Global State ───────────────────────────────────────────────────────────

var (
	users    = &UserManager{path: UsersFile}
	sessions = &SessionStore{path: SessionsFile}
)

// ─── User Manager ───────────────────────────────────────────────────────────

type UserManager struct {
	mu    sync.RWMutex
	users map[string]*User
	path  string
}

func (um *UserManager) Load() error {
	um.mu.Lock()
	defer um.mu.Unlock()
	um.users = make(map[string]*User)
	data, err := os.ReadFile(um.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // first run
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &um.users)
}

func (um *UserManager) Save() error {
	um.mu.RLock()
	defer um.mu.RUnlock()
	data, err := json.MarshalIndent(um.users, "", "  ")
	if err != nil {
		return err
	}
	tmp := um.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, um.path)
}

func (um *UserManager) Create(username, password string) error {
	um.mu.Lock()
	defer um.mu.Unlock()
	if _, exists := um.users[username]; exists {
		return errors.New("username already taken")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return err
	}
	um.users[username] = &User{
		Username:     username,
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	return um.saveLocked()
}

func (um *UserManager) saveLocked() error {
	data, err := json.MarshalIndent(um.users, "", "  ")
	if err != nil {
		return err
	}
	tmp := um.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, um.path)
}

func (um *UserManager) Exists(username string) bool {
	um.mu.RLock()
	defer um.mu.RUnlock()
	_, ok := um.users[username]
	return ok
}

// ─── Session Store ──────────────────────────────────────────────────────────

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	path     string
}

func (ss *SessionStore) Load() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions = make(map[string]*Session)
	data, err := os.ReadFile(ss.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &ss.sessions)
}

func (ss *SessionStore) Save() error {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	data, err := json.MarshalIndent(ss.sessions, "", "  ")
	if err != nil {
		return err
	}
	tmp := ss.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, ss.path)
}

func (ss *SessionStore) Create(username string) (*Session, error) {
	token, err := genToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := genToken(16)
	if err != nil {
		return nil, err
	}
	session := &Session{
		Token:     token,
		Username:  username,
		CSRFToken: csrf,
		ExpiresAt: time.Now().Add(SessionTTL),
	}
	ss.mu.Lock()
	ss.sessions[token] = session
	ss.mu.Unlock()
	if err := ss.Save(); err != nil {
		return nil, err
	}
	return session, nil
}

func (ss *SessionStore) Get(token string) (*Session, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	session, ok := ss.sessions[token]
	if !ok {
		return nil, false
	}
	if session.ExpiresAt.Before(time.Now()) {
		return nil, false
	}
	return session, true
}

func (ss *SessionStore) Delete(token string) {
	ss.mu.Lock()
	delete(ss.sessions, token)
	ss.mu.Unlock()
	ss.Save()
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func genToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
}

func verifyPassword(password string, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}

func humanSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div := int64(unit)
	exp := 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

func isTextFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".html", ".htm", ".css", ".js", ".txt", ".md", ".xml", ".json",
		".csv", ".svg", ".yaml", ".yml", ".ini", ".conf", ".log", "":
		return true
	}
	return false
}

func sanitizeFilename(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("filename cannot be empty")
	}
	if strings.ContainsAny(name, "/\\") {
		return "", errors.New("filename cannot contain path separators")
	}
	if name == "." || name == ".." {
		return "", errors.New("invalid filename")
	}
	name = strings.ReplaceAll(name, "\x00", "")
	if name == "" {
		return "", errors.New("filename cannot be empty")
	}
	return name, nil
}

// ─── File Operations ───────────────────────────────────────────────────────

func userDir(username string) string {
	return filepath.Join(SitesDir, username)
}

func safeFilePath(username, filename string) (string, error) {
	cleanName, err := sanitizeFilename(filename)
	if err != nil {
		return "", err
	}
	ud := userDir(username)
	fullPath := filepath.Join(ud, cleanName)

	// Verify path stays inside the user directory
	absUD, err := filepath.Abs(ud)
	if err != nil {
		return "", err
	}
	absFP, err := filepath.Abs(fullPath)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absFP, absUD+string(filepath.Separator)) {
		return "", errors.New("path traversal detected")
	}
	return fullPath, nil
}

func listFiles(username string) ([]FileInfo, error) {
	ud := userDir(username)
	entries, err := os.ReadDir(ud)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var files []FileInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue // skip dotfiles
		}
		files = append(files, FileInfo{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name < files[j].Name
	})
	return files, nil
}

func totalSizeAndCount(username string) (int64, int, error) {
	ud := userDir(username)
	entries, err := os.ReadDir(ud)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	var total int64
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		total += info.Size()
		count++
	}
	return total, count, nil
}

// canWrite checks whether writing newContent to filename would violate
// the space or file-count constraints.
func canWrite(username, filename string, newSize int64) error {
	ud := userDir(username)
	entries, err := os.ReadDir(ud)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	var total int64
	count := 0
	isNew := true

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if e.Name() == filename {
			isNew = false // replacing existing file: don't double-count
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		total += info.Size()
		count++
	}

	total += newSize
	if isNew {
		count++
	}

	if total > MaxSpace {
		return fmt.Errorf("space limit exceeded: %s / %s",
			humanSize(total), humanSize(MaxSpace))
	}
	if count > MaxFiles {
		return fmt.Errorf("file limit exceeded: %d / %d", count, MaxFiles)
	}
	return nil
}

// ─── Template Functions ────────────────────────────────────────────────────

var templateFuncs = template.FuncMap{
	"humanSize":  humanSize,
	"isTextFile": isTextFile,
	"add":        func(a, b int) int { return a + b },
}

func parseTemplates() map[string]*template.Template {
	templates := make(map[string]*template.Template)

	pages := map[string]string{
		"index":   tmplIndex,
		"signup":  tmplSignup,
		"login":   tmplLogin,
		"manage":  tmplManage,
		"edit":    tmplEdit,
		"tenants": tmplTenants,
	}

	for name, pageContent := range pages {
		tmpl := template.Must(template.New("").Funcs(templateFuncs).Parse(
			tmplBase + tmplStyles + tmplHeader + tmplFooter + pageContent))
		templates[name] = tmpl
	}

	return templates
}

var templates map[string]*template.Template

func render(w http.ResponseWriter, name string, data ViewData) {
	tmpl, ok := templates[name]
	if !ok {
		http.Error(w, "Template not found: "+name, http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		log.Printf("template error: %v", err)
	}
}

// ─── Middleware ─────────────────────────────────────────────────────────────

type ctxKey string

const sessionKey ctxKey = "session"

func withSession(r *http.Request, session *Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionKey, session))
}

func getSession(r *http.Request) *Session {
	val := r.Context().Value(sessionKey)
	if val == nil {
		return nil
	}
	s, ok := val.(*Session)
	if !ok {
		return nil
	}
	return s
}

func requireAuth(w http.ResponseWriter, r *http.Request) *Session {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	session, ok := sessions.Get(cookie.Value)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	return session
}

func verifyCSRF(r *http.Request, expected string) bool {
	form := r.FormValue("csrf_token")
	return subtle.ConstantTimeCompare([]byte(form), []byte(expected)) == 1
}

// ─── Handlers ───────────────────────────────────────────────────────────────

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	data := ViewData{
		Title: "TENEMENT — Digital Tenement Hosting",
	}
	render(w, "index", data)
}

func handleSignup(w http.ResponseWriter, r *http.Request, session *Session) {
	if r.Method != http.MethodPost {
		data := ViewData{
			Title:     "Sign Up — TENEMENT",
			CSRFToken: session.CSRFToken,
		}
		render(w, "signup", data)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	data := ViewData{
		Title:     "Sign Up — TENEMENT",
		CSRFToken: session.CSRFToken,
	}

	// Validate username
	if !UsernameRegex.MatchString(username) {
		data.Error = "Username must be 2-32 characters: letters, numbers, hyphens, underscores. Must start with a letter or number."
		render(w, "signup", data)
		return
	}

	// Validate password
	if len(password) < 8 {
		data.Error = "Password must be at least 8 characters."
		render(w, "signup", data)
		return
	}
	if password != confirm {
		data.Error = "Passwords do not match."
		render(w, "signup", data)
		return
	}

	// Create user
	if err := users.Create(username, password); err != nil {
		data.Error = err.Error()
		render(w, "signup", data)
		return
	}

	// Create site directory
	os.MkdirAll(userDir(username), 0755)

	// Create sessions dir if needed
	os.MkdirAll(SitesDir, 0755)

	// Log the user in
	session, err := sessions.Create(username)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})

	log.Printf("New tenant: ~%s", username)
	http.Redirect(w, r, "/manage", http.StatusSeeOther)
}

func handleLogin(w http.ResponseWriter, r *http.Request, session *Session) {
	if r.Method != http.MethodPost {
		data := ViewData{
			Title:     "Login — TENEMENT",
			CSRFToken: session.CSRFToken,
		}
		render(w, "login", data)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	data := ViewData{
		Title:     "Login — TENEMENT",
		CSRFToken: session.CSRFToken,
	}

	if !users.Exists(username) {
		data.Error = "No such tenant. Did you sign up?"
		render(w, "login", data)
		return
	}

	userRecord, ok := loadUserUnsafe(username)
	if !ok {
		data.Error = "Authentication error."
		render(w, "login", data)
		return
	}

	if err := bcrypt.CompareHashAndPassword(userRecord.PasswordHash, []byte(password)); err != nil {
		data.Error = "Wrong password."
		render(w, "login", data)
		return
	}

	session, err := sessions.Create(username)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})

	log.Printf("Tenant logged in: ~%s", username)
	http.Redirect(w, r, "/manage", http.StatusSeeOther)
}

// loadUserUnsafe returns the user record without authentication.
// It does NOT verify the password.
func loadUserUnsafe(username string) (*User, bool) {
	users.mu.RLock()
	defer users.mu.RUnlock()
	u, ok := users.users[username]
	return u, ok
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(CookieName)
	if err == nil {
		sessions.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // delete
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleManage(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		session = requireAuth(w, r)
		if session == nil {
			return
		}
	}

	username := session.Username

	// Load error/success from query params (after redirect)
	errorMsg := r.URL.Query().Get("error")
	successMsg := r.URL.Query().Get("success")

	files, err := listFiles(username)
	if err != nil {
		files = nil
	}

	usedSize, usedFiles, err := totalSizeAndCount(username)
	if err != nil {
		usedSize = 0
		usedFiles = 0
	}

	data := ViewData{
		Title:       "Manage — TENEMENT",
		Username:    username,
		CSRFToken:   session.CSRFToken,
		Files:       files,
		UsedSize:    usedSize,
		UsedFiles:   usedFiles,
		MaxSize:     MaxSpace,
		MaxFiles:    MaxFiles,
		SizePercent: float64(usedSize) / float64(MaxSpace) * 100,
		FilesPercent: float64(usedFiles) / float64(MaxFiles) * 100,
		Error:       errorMsg,
		Success:     successMsg,
	}
	render(w, "manage", data)
}

func handleEdit(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		session = requireAuth(w, r)
		if session == nil {
			return
		}
	}

	username := session.Username
	filename := r.URL.Query().Get("file")
	errorMsg := r.URL.Query().Get("error")
	successMsg := r.URL.Query().Get("success")

	// Default to index.html if no file specified
	if filename == "" {
		filename = "index.html"
	}

	var content string
	var fileSize int64

	fp, err := safeFilePath(username, filename)
	if err != nil {
		vd := ViewData{
			Title:      filename + " — Edit — TENEMENT",
			Username:   username,
			CSRFToken:  session.CSRFToken,
			Filename:   filename,
			Content:    "",
			FileSize:   0,
			Error:      err.Error(),
		}
		render(w, "edit", vd)
		return
	}

	fileContent, err := os.ReadFile(fp)
	if err != nil && !os.IsNotExist(err) {
		vd := ViewData{
			Title:      filename + " — Edit — TENEMENT",
			Username:   username,
			CSRFToken:  session.CSRFToken,
			Filename:   filename,
			Content:    "",
			FileSize:   0,
			Error:      "Failed to read file: " + err.Error(),
		}
		render(w, "edit", vd)
		return
	}

	if len(fileContent) > 0 {
		content = string(fileContent)
		fileSize = int64(len(fileContent))
	}

	// Compute usage stats for the editor meta
	usedSize, usedFiles, _ := totalSizeAndCount(username)

	vd := ViewData{
		Title:      filename + " — Edit — TENEMENT",
		Username:   username,
		CSRFToken:  session.CSRFToken,
		Filename:   filename,
		Content:    content,
		FileSize:   fileSize,
		UsedSize:   usedSize,
		UsedFiles:  usedFiles,
		MaxSize:    MaxSpace,
		MaxFiles:   MaxFiles,
		Error:      errorMsg,
		Success:    successMsg,
	}
	render(w, "edit", vd)
}

func handleCreate(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	filename := strings.TrimSpace(r.FormValue("filename"))

	cleanName, err := sanitizeFilename(filename)
	if err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery(err.Error()), http.StatusSeeOther)
		return
	}

	// Check constraints for a new file
	if err := canWrite(session.Username, cleanName, 0); err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery(fmt.Sprintf("Cannot create file: %v", err)), http.StatusSeeOther)
		return
	}

	// Redirect to editor
	http.Redirect(w, r, "/manage/edit?file="+escapeQuery(cleanName), http.StatusSeeOther)
}

func handleSave(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := session.Username
	filename := strings.TrimSpace(r.FormValue("filename"))
	content := r.FormValue("content")

	cleanName, err := sanitizeFilename(filename)
	if err != nil {
		http.Redirect(w, r, "/manage/edit?file="+escapeQuery(filename)+"&error="+escapeQuery(err.Error()), http.StatusSeeOther)
		return
	}

	// Check constraints
	if err := canWrite(username, cleanName, int64(len(content))); err != nil {
		http.Redirect(w, r, "/manage/edit?file="+escapeQuery(cleanName)+"&error="+escapeQuery(fmt.Sprintf("Save failed: %v", err)), http.StatusSeeOther)
		return
	}

	fp, err := safeFilePath(username, cleanName)
	if err != nil {
		http.Redirect(w, r, "/manage/edit?file="+escapeQuery(cleanName)+"&error="+escapeQuery(err.Error()), http.StatusSeeOther)
		return
	}

	if err := os.MkdirAll(filepath.Dir(fp), 0755); err != nil {
		log.Printf("mkdir error: %v", err)
	}

	if err := os.WriteFile(fp, []byte(content), 0644); err != nil {
		http.Redirect(w, r, "/manage/edit?file="+escapeQuery(cleanName)+"&error="+escapeQuery("Failed to save: "+err.Error()), http.StatusSeeOther)
		return
	}

	log.Printf("Tenant ~%s saved %s (%s)", username, cleanName, humanSize(int64(len(content))))
	http.Redirect(w, r, "/manage?success="+escapeQuery(fmt.Sprintf("Saved %s (%s)", cleanName, humanSize(int64(len(content))))), http.StatusSeeOther)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := session.Username

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, MaxSpace+1024)
	if err := r.ParseMultipartForm(MaxSpace + 1024); err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery("Upload too large (max 2048 KB)"), http.StatusSeeOther)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery("No file selected"), http.StatusSeeOther)
		return
	}
	defer file.Close()

	filename := header.Filename
	cleanName, err := sanitizeFilename(filename)
	if err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery(err.Error()), http.StatusSeeOther)
		return
	}

	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery("Failed to read upload"), http.StatusSeeOther)
		return
	}

	// Check constraints
	if err := canWrite(username, cleanName, int64(len(content))); err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery(fmt.Sprintf("Upload rejected: %v", err)), http.StatusSeeOther)
		return
	}

	// Save file
	fp, err := safeFilePath(username, cleanName)
	if err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery(err.Error()), http.StatusSeeOther)
		return
	}
	if err := os.MkdirAll(filepath.Dir(fp), 0755); err != nil {
		log.Printf("mkdir error: %v", err)
	}
	if err := os.WriteFile(fp, content, 0644); err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery("Failed to save file"), http.StatusSeeOther)
		return
	}

	log.Printf("Tenant ~%s uploaded %s (%s)", username, cleanName, humanSize(int64(len(content))))
	http.Redirect(w, r, "/manage?success="+escapeQuery("Uploaded "+cleanName), http.StatusSeeOther)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := session.Username
	filename := strings.TrimSpace(r.FormValue("filename"))

	fp, err := safeFilePath(username, filename)
	if err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery(err.Error()), http.StatusSeeOther)
		return
	}

	if err := os.Remove(fp); err != nil {
		http.Redirect(w, r, "/manage?error="+escapeQuery("Failed to delete: "+err.Error()), http.StatusSeeOther)
		return
	}

	log.Printf("Tenant ~%s deleted %s", username, filename)
	http.Redirect(w, r, "/manage?success="+escapeQuery("Deleted "+filename), http.StatusSeeOther)
}

func handleTenants(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(SitesDir)
	if err != nil {
		entries = nil
	}
	var tenants []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			tenants = append(tenants, e.Name())
		}
	}
	sort.Strings(tenants)

	data := ViewData{
		Title:       "Tenants — TENEMENT",
		Tenants:     tenants,
		TenantCount: len(tenants),
	}
	render(w, "tenants", data)
}

func handlePublicSite(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Parse /~username/optional/path
	if !strings.HasPrefix(path, "/~") {
		http.NotFound(w, r)
		return
	}

	rest := path[2:] // strip "/~"
	parts := strings.SplitN(rest, "/", 2)
	username := parts[0]

	// Validate username
	if !UsernameRegex.MatchString(username) {
		http.NotFound(w, r)
		return
	}

	// Determine requested file
	var reqFile string
	if len(parts) == 1 {
		// /~username → redirect to /~username/
		http.Redirect(w, r, "/~"+username+"/", http.StatusSeeOther)
		return
	}
	reqFile = parts[1]

	// Default to index.html for directory root
	if reqFile == "" || reqFile == "/" {
		reqFile = "index.html"
	}

	// Clean the file path and prevent traversal
	cleanFile := filepath.Clean(reqFile)
	if strings.Contains(cleanFile, "..") || filepath.IsAbs(cleanFile) {
		http.NotFound(w, r)
		return
	}

	// Prevent dotfile access
	if strings.HasPrefix(filepath.Base(cleanFile), ".") {
		http.NotFound(w, r)
		return
	}

	fullPath := filepath.Join(userDir(username), cleanFile)

	// Verify path stays inside user directory
	absUD, _ := filepath.Abs(userDir(username))
	absFP, _ := filepath.Abs(fullPath)
	if !strings.HasPrefix(absFP, absUD+string(filepath.Separator)) {
		http.NotFound(w, r)
		return
	}

	// Check if file exists
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) && (cleanFile == "index.html" || reqFile == "") {
			// Show vacant page
			serveVacantPage(w, username)
			return
		}
		http.NotFound(w, r)
		return
	}

	// Don't serve directories
	if info.IsDir() {
		http.NotFound(w, r)
		return
	}

	// Serve the file
	http.ServeFile(w, r, fullPath)
}

func serveVacantPage(w http.ResponseWriter, username string) {
	safeUser := html.EscapeString(username)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	page := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>~` + safeUser + ` — TENEMENT</title>
<style>
body{margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8f4f0;color:#333}
.container{max-width:600px;margin:4rem auto;padding:2rem;text-align:center}
h1{font-size:2rem;margin-bottom:1rem}
p{color:#999;margin:1rem 0}
code{background:#e8e0d0;padding:0.1rem 0.3rem;border-radius:3px}
a{color:#6a4c3d}
</style>
</head>
<body>
<div class="container">
<h1>~` + safeUser + `</h1>
<p>This tenement has no front door yet.</p>
<p>No <code>index.html</code> has been placed here.</p>
<p><a href="/">Browse other tenements &rarr;</a></p>
</div>
</body>
</html>`

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(page))
}

func withSecurityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next(w, r)
	}
}

// ─── URL Escape Helpers ─────────────────────────────────────────────────────

func escapeQuery(s string) string {
	return url.QueryEscape(s)
}

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	// Create data directories
	for _, dir := range []string{DataDir, SitesDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Cannot create directory %s: %v", dir, err)
		}
	}

	// Load data
	if err := users.Load(); err != nil {
		log.Fatalf("Cannot load users: %v", err)
	}
	if err := sessions.Load(); err != nil {
		log.Fatalf("Cannot load sessions: %v", err)
	}

	// Parse templates
	templates = parseTemplates()

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", withSecurityHeaders(dispatch))

	// Determine listen address
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("TENEMENT — digital tenement hosting")
	log.Printf("Listening on http://localhost%s", addr)
	log.Printf("Constraints: %s space, %d files per tenant", humanSize(MaxSpace), MaxFiles)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ─── Dispatcher ─────────────────────────────────────────────────────────────

func dispatch(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	// Health check (no auth)
	if path == "/healthz" {
		handleHealthz(w, r)
		return
	}

	// Public tenant site: /~username/...
	if strings.HasPrefix(path, "/~") {
		handlePublicSite(w, r)
		return
	}

	// Public pages (redirect if already logged in)
	switch path {
	case "/":
		if session := loadSession(r); session != nil && session.Username != "" {
			http.Redirect(w, r, "/manage", http.StatusSeeOther)
			return
		}
		handleIndex(w, r)
		return
	case "/signup":
		if session := loadSession(r); session != nil && session.Username != "" {
			http.Redirect(w, r, "/manage", http.StatusSeeOther)
			return
		}
		tempSession := ensureTempSession(w, r)
		if tempSession == nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		if method == "POST" && !verifyCSRF(r, tempSession.CSRFToken) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		handleSignup(w, r, tempSession)
		return
	case "/login":
		if session := loadSession(r); session != nil && session.Username != "" {
			http.Redirect(w, r, "/manage", http.StatusSeeOther)
			return
		}
		tempSession := ensureTempSession(w, r)
		if tempSession == nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		if method == "POST" && !verifyCSRF(r, tempSession.CSRFToken) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		handleLogin(w, r, tempSession)
		return
	case "/tenants":
		handleTenants(w, r)
		return
	}

	// Auth-required routes
	session := loadSession(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	r = withSession(r, session)

	// Logout (POST only, CSRF required)
	if path == "/logout" {
		if method != "POST" {
			http.NotFound(w, r)
			return
		}
		if !verifyCSRF(r, session.CSRFToken) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		handleLogout(w, r)
		return
	}

	// GET routes for manage/edit
	if method != "POST" {
		switch path {
		case "/manage":
			handleManage(w, r)
			return
		case "/manage/edit":
			handleEdit(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}

	// POST routes (CSRF required)
	if !verifyCSRF(r, session.CSRFToken) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	switch path {
	case "/manage/create":
		handleCreate(w, r)
	case "/manage/save":
		handleSave(w, r)
	case "/manage/upload":
		handleUpload(w, r)
	case "/manage/delete":
		handleDelete(w, r)
	default:
		http.NotFound(w, r)
	}
}

// loadSession reads the session cookie and returns the session.
func loadSession(r *http.Request) *Session {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return nil
	}
	session, ok := sessions.Get(cookie.Value)
	if !ok {
		return nil
	}
	return session
}

// ensureTempSession generates a session for unauthenticated pages that
// need a CSRF token. These sessions are empty (no username) and used
// only for CSRF validation on the signup/login forms.
func ensureTempSession(w http.ResponseWriter, r *http.Request) *Session {
	// Check if there's already a session
	if session := loadSession(r); session != nil {
		if session.Username == "" {
			return session // already a temp session
		}
		return session
	}

	// Create a temp session with empty username
	token, err := genToken(32)
	if err != nil {
		return nil
	}
	csrf, err := genToken(16)
	if err != nil {
		return nil
	}
	session := &Session{
		Token:     token,
		Username:  "",
		CSRFToken: csrf,
		ExpiresAt: time.Now().Add(SessionTTL),
	}
	sessions.mu.Lock()
	sessions.sessions[token] = session
	sessions.mu.Unlock()
	sessions.Save()

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})
	return session
}

// ─── Templates ──────────────────────────────────────────────────────────────

const tmplStyles = `{{define "styles"}}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, system-ui, sans-serif;
  background: #f8f4f0;
  color: #333;
  line-height: 1.6;
}
.container { max-width: 800px; margin: 0 auto; padding: 2rem; }
a { color: #6a4c3d; text-decoration: none; }
a:hover { text-decoration: underline; }
code { background: #e8e0d0; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.9em; }
h1 { font-size: 2.5rem; font-weight: 800; margin-bottom: 1rem; }
h2 { font-size: 1.3rem; font-weight: 700; margin: 1.5rem 0 0.5rem; }
p { margin: 0.5rem 0; }

/* Header */
header {
  background: #fff;
  border-bottom: 1px solid #e0d8cd;
  padding: 0.8rem 2rem;
  position: sticky;
  top: 0;
  z-index: 10;
}
header .row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  max-width: 800px;
  margin: 0 auto;
}
header .logo { font-size: 1.2rem; font-weight: 800; }
header .logo a { color: #333; }
header .auth { font-size: 0.9rem; margin-left: auto; }
header .auth span { color: #999; }
header .auth a { margin-left: 0.5rem; color: #666; }

/* Footer */
footer {
  border-top: 1px solid #e0d8cd;
  padding: 1rem 2rem;
  text-align: center;
  font-size: 0.8rem;
  color: #aaa;
}

/* Stats grid */
.stats {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.5rem;
  margin: 2rem 0;
}
.stat {
  background: #fff;
  padding: 1rem;
  border: 1px solid #e0d8cd;
  text-align: center;
}
.stat .num { font-size: 1.5rem; font-weight: 700; color: #6a4c3d; }
.stat .lbl { font-size: 0.65rem; color: #aaa; text-transform: uppercase; letter-spacing: 0.5px; }

/* Progress */
.progress-bar {
  height: 8px;
  background: #e0d8cd;
  overflow: hidden;
  margin: 0.5rem 0 1rem;
  border-radius: 0;
}
.progress-fill {
  height: 100%;
  background: #6a4c3d;
  transition: width 0.3s ease;
}
.progress-fill.warn { background: #c47a3a; }
.progress-fill.danger { background: #b33a2e; }

/* Forms */
form { margin: 1rem 0; }
input[type="text"], input[type="password"], input[type="file"], textarea {
  width: 100%;
  padding: 0.6rem;
  border: 1px solid #ccc;
  font: inherit;
  background: #fff;
}
input:focus, textarea:focus {
  outline: 2px solid #8a5a44;
  outline-offset: -1px;
}
button {
  background: #6a4c3d;
  color: #fff;
  border: none;
  padding: 0.6rem 1.2rem;
  font: inherit;
  cursor: pointer;
  font-size: 0.9rem;
}
button:hover { background: #5a3d2f; }
button.secondary {
  background: #fff;
  color: #333;
  border: 1px solid #ccc;
}
button.secondary:hover { background: #f0ebe6; }
button.danger { background: #b33a2e; }
button.danger:hover { background: #8a2e24; }
.btn {
  display: inline-block;
  padding: 0.6rem 1.2rem;
  font: inherit;
  cursor: pointer;
  text-align: center;
  font-size: 0.9rem;
  border: 1px solid transparent;
}
.btn-primary { background: #6a4c3d; color: #fff; }
.btn-primary:hover { background: #5a3d2f; }
.btn-link {
  background: none;
  border: none;
  color: #6a4c3d;
  cursor: pointer;
  padding: 0;
  text-decoration: underline;
  font-size: inherit;
}
.btn-link:hover { color: #5a3d2f; }
.inline-form { display: inline; }

/* Table */
table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
th, td { padding: 0.6rem 0.4rem; text-align: left; border-bottom: 1px solid #eee; }
th { font-size: 0.7rem; text-transform: uppercase; color: #aaa; font-weight: 600; letter-spacing: 0.5px; }
td a { color: #888; font-size: 0.85rem; }
td a:hover { color: #333; }

/* Cards */
.card {
  background: #fff;
  border: 1px solid #e0d8cd;
  padding: 1.5rem;
  margin: 1rem 0;
}

/* Editor */
.editor-toolbar {
  display: flex;
  gap: 0.8rem;
  margin-bottom: 0.6rem;
}
.editor-toolbar input[type="text"] { flex: 1; }
textarea.editor {
  width: 100%;
  height: 70vh;
  min-height: 350px;
  font-family: 'Courier New', Courier, monospace;
  font-size: 0.85rem;
  padding: 1rem;
  border: 1px solid #ccc;
  background: #fff;
  resize: vertical;
  tab-size: 2;
}
.editor-meta {
  display: flex;
  justify-content: space-between;
  color: #aaa;
  font-size: 0.8rem;
  margin-top: 0.5rem;
}

/* Alerts */
.alert {
  padding: 0.8rem 1rem;
  margin: 0.5rem 0;
  border-radius: 4px;
  font-size: 0.9rem;
}
.alert-error { color: #b33a2e; background: #ffe0dd; border: 1px solid #f5c6c1; }
.alert-success { color: #1a7f37; background: #e6f4ea; border: 1px solid #a3e0b5; }

/* Landing */
.hero { text-align: center; padding: 3rem 1rem; }
.logo-big { font-size: 3rem; font-weight: 900; color: #333; margin-bottom: 0.5rem; }
.subtitle { font-size: 1.1rem; color: #888; max-width: 560px; margin: 0 auto 2rem; }
.tagline { font-size: 0.8rem; color: #aaa; margin-top: 2rem; }

/* Constraint list */
.constraints { list-style: none; margin: 1.5rem 0; }
.constraints li {
  display: flex;
  align-items: center;
  padding: 0.4rem 0;
  font-size: 0.9rem;
}
.constraints li strong { color: #6a4c3d; min-width: 120px; }
.constraints li span { color: #888; flex: 1; }
{{end}}`

const tmplBase = `{{define "base"}}
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
{{template "styles"}}
</head>
<body>
{{template "header" .}}
<main class="container">
{{template "content" .}}
</main>
{{template "footer" .}}
</body>
</html>
{{end}}`

const tmplHeader = `{{define "header"}}
<header>
  <div class="row">
    <div class="logo"><a href="/">TENEMENT</a></div>
    <div class="auth">
      {{if .Username}}
      <span>~{{.Username}}</span>
      <a href="/manage">Manage</a>
      <form method="POST" action="/logout" class="inline-form">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <button type="submit" class="btn-link">Logout</button>
      </form>
      {{else}}
      <a href="/login">Login</a>
      <a href="/signup">Sign Up</a>
      {{end}}
    </div>
  </div>
</header>
{{end}}`

const tmplFooter = `{{define "footer"}}
<footer>
  <p>TENEMENT · A digital tenement · No tracking · No database · No CGI · No PHP</p>
</footer>
{{end}}`

const tmplIndex = `{{define "content"}}
<div class="hero">
  <div class="logo-big">TENEMENT</div>
  <p class="subtitle">
    A digital tenement for your tiny homepage.<br><br>
    Every tenant gets a cramped little space — 2048 KB of storage, 128 files —
    and the bare essentials to put up a website. The constraints are the feature.
  </p>
  <div class="stats">
    <div class="stat"><div class="num">2048 KB</div><div class="lbl">Free Space</div></div>
    <div class="stat"><div class="num">128</div><div class="lbl">Files</div></div>
    <div class="stat"><div class="num">0</div><div class="lbl">Databases</div></div>
    <div class="stat"><div class="num">0</div><div class="lbl">Tracking</div></div>
  </div>
  <ul class="constraints">
    <li><strong>EVERY TENANT GETS:</strong></li>
    <li><strong>URL:</strong><span>tenement.city/~username/</span></li>
    <li><strong>STORAGE:</strong><span>2048 KB of files. No more.</span></li>
    <li><strong>FILES:</strong><span>128 files max. Count them.</span></li>
    <li><strong>LANGUAGE:</strong><span>HTML, CSS, text — your choice.</span></li>
    <li><strong>NO:</strong><span>CutCGI, PHP, databases, or tracking. Just files.</span></li>
  </ul>
  <p style="margin: 2rem 0 0.5rem;">
    <a href="/signup" class="btn btn-primary" style="font-size:1.1rem;padding:0.8rem 1.5rem;">SIGN UP FREE</a>
  </div>
  <p><small>Already have a tenement? <a href="/login">Log in</a></small></p>
  <p><small><a href="/tenants">Browse all tenants</a></small></p>
  <p class="tagline">Built with Go · No dependencies beyond the standard library · Single binary</p>
</div>
{{end}}`

const tmplSignup = `{{define "content"}}
<div class="card">
  <h2>Sign Up for a Tenement</h2>
  {{if .Error}}
  <div class="alert alert-error">{{.Error}}</div>
  {{end}}
  <form method="POST" action="/signup">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <p style="margin-bottom:0.8rem"><label>Choose a username<br>
      <input type="text" name="username" placeholder="tenement.city/~___" required>
    </label></p>
    <p style="margin-bottom:0.8rem"><label>Password (min 8 chars)<br>
      <input type="password" name="password" required>
    </label></p>
    <p style="margin-bottom:0.8rem"><label>Confirm password<br>
      <input type="password" name="confirm" required>
    </label></p>
    <button type="submit" class="btn btn-primary">Claim Your Tenement</button>
  </form>
  <p style="margin-top:1.5rem"><small>
    By signing up you acknowledge you get <strong>2048 KB</strong> and <strong>128 files</strong>, zero databases, zero tracking.
  </small></p>
</div>
{{end}}`

const tmplLogin = `{{define "content"}}
<div class="card">
  <h2>Log In to Your Tenement</h2>
  {{if .Error}}
  <div class="alert alert-error">{{.Error}}</div>
  {{end}}
  <form method="POST" action="/login">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <p style="margin-bottom:0.8rem"><label>Username<br>
      <input type="text" name="username" placeholder="your tenement name" required>
    </label></p>
    <p style="margin-bottom:0.8rem"><label>Password<br>
      <input type="password" name="password" required>
    </label></p>
    <button type="submit" class="btn btn-primary">Open Your Door</button>
  </form>
  <p style="margin-top:1.5rem"><small>
    No tenement yet? <a href="/signup">Sign up</a> — takes 2 seconds.
  </small></p>
</div>
{{end}}`

const tmplManage = `{{define "content"}}
<div style="margin-bottom:1.5rem">
  <h2>Your Tenement: ~{{.Username}}</h2>

  {{if .Error}}
  <div class="alert alert-error">{{.Error}}</div>
  {{end}}
  {{if .Success}}
  <div class="alert alert-success">{{.Success}}</div>
  {{end}}

  <div class="stat">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <span><strong>{{.UsedFiles}}</strong> / {{.MaxFiles}} files</span>
      <span>{{humanSize .UsedSize}} / {{humanSize .MaxSize}}</span>
    </div>
    <div class="progress-bar">
      <div class="progress-fill" style="width:{{.SizePercent}}%"></div>
    </div>
  </div>
</div>

{{if .Files}}
<table>
  <thead>
    <tr>
      <th>File</th>
      <th>Size</th>
      <th>Modified</th>
      <th style="text-align:right">Actions</th>
    </tr>
  </thead>
  <tbody>
    {{range .Files}}
    <tr>
      <td>{{.Name}}</td>
      <td>{{humanSize .Size}}</td>
      <td>{{.ModTime.Format "Jan 2, 2006"}}</td>
      <td style="text-align:right">
        {{if isTextFile .Name}}
        <a href="/manage/edit?file={{.Name | urlquery}}">Edit</a>
        {{end}}
        <form method="POST" action="/manage/delete" class="inline-form" onsubmit="return confirm('Delete {{.Name}}? This cannot be undone.')">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="filename" value="{{.Name}}">
          <button type="submit" class="btn-link" style="color:#b33a2e">Delete</button>
        </form>
      </td>
    </tr>
    {{end}}
  </tbody>
</table>
{{else}}
<div class="card">
  <p style="color:#999">No files yet. Create one to get started.</p>
</div>
{{end}}

<div class="card">
  <h2 style="margin-top:0">Upload a File</h2>
  <form method="POST" action="/manage/upload" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <input type="file" name="file" required>
    <button type="submit" class="btn btn-primary" style="margin-top:0.5rem">Upload</button>
  </form>
  <p style="margin-top:0.8rem"><small>
    Use this to upload images, fonts, or binary files. For text (HTML, CSS, JS),
    use the editor below.
  </small></p>
</div>

<div class="card">
  <h2 style="margin-top:0">Create a New File</h2>
  <form method="POST" action="/manage/create" class="inline-form">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <input type="text" name="filename" placeholder="e.g. index.html" required style="max-width:300px;display:inline-block">
    <button type="submit" class="btn btn-primary">Create → Edit</button>
  </form>
  <p style="margin-top:0.8rem"><small>
    Tip: Create <code>index.html</code> first — it becomes your homepage at <code>/~{{.Username}}/</code>.
  </small></p>
</div>
{{end}}`

const tmplEdit = `{{define "content"}}
<div style="margin-bottom:1.5rem">
  <h2 style="display:flex;align-items:center;gap:0.5rem">
    <span>Editing:</span>
    <span style="font-family:monospace;font-size:1rem">{{.Filename}}</span>
  </h2>

  {{if .Error}}
  <div class="alert alert-error">{{.Error}}</div>
  {{end}}
  {{if .Success}}
  <div class="alert alert-success">{{.Success}}</div>
  {{end}}

  <form method="POST" action="/manage/save">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <div class="editor-toolbar">
      <input type="text" name="filename" value="{{.Filename}}" placeholder="filename.html" required>
      <button type="submit" class="btn btn-primary">Save</button>
    </div>
    <textarea name="content" class="editor" placeholder="Write your HTML here..." spellcheck="false">{{.Content}}</textarea>
    <div class="editor-meta">
      <span>{{humanSize .FileSize}}</span>
      <span>Space used: {{$.UsedFiles}} of {{$.MaxFiles}} files — {{humanSize $.UsedSize}} of {{humanSize $.MaxSize}}</span>
    </div>
  </form>
  <p style="margin-top:1rem">
    <a href="/manage" class="btn-link">← Back to file manager</a>
  </p>
</div>
{{end}}`

const tmplTenants = `{{define "content"}}
<div style="margin-bottom:1.5rem">
  <h2>All Tenants</h2>
  <p>{{.TenantCount}} tenements in the building.</p>
</div>

{{if .Tenants}}
<table>
  <thead>
    <tr>
      <th>Username</th>
      <th>Site</th>
    </tr>
  </thead>
  <tbody>
    {{range .Tenants}}
    <tr>
      <td>~{{.}}</td>
      <td><a href="/~{{. | urlquery}}/">View site</a></td>
    </tr>
    {{end}}
  </tbody>
</table>
{{else}}
<div class="card">
  <p style="color:#999">No tenants yet. Be the first to sign up!</p>
</div>
{{end}}
{{end}}`
