package main

import (
	"database/sql"
	"log"
	"net/http"
	"os" // 新增: 用於讀取環境變數 (資料庫連線字串)
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq" // 變更: 使用 PostgreSQL/CockroachDB 驅動
)

// --- 雙資料庫變數 ---
// 變數將透過環境變數連線到 CockroachDB 的不同資料庫或 Schema。
var userDB *sql.DB    // 用於 users 資料表 (連線字串來自 USER_DB_URL)
var projectDB *sql.DB // 用於 projects 和 tasks 資料表 (連線字串來自 PROJECT_DB_URL)

// --- 資料庫模型 (Structs) ---
type Task struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Start        string `json:"start"`
	DurationDays int    `json:"durationDays"`
	Priority     int    `json:"priority"`
	Color        string `json:"color"`
}
type Project struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Department string `json:"department"`
}
type User struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	Name       string `json:"name"`
	Department string `json:"department"`
	IsAdmin    int    `json:"is_admin"` // 0 = false, 1 = true
}
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}
type ProjectRequest struct {
	Name       string `json:"name"       binding:"required"`
	Department string `json:"department" binding:"required"`
}
type CreateUserRequest struct {
	Username   string `json:"username"   binding:"required"`
	Password   string `json:"password"   binding:"required"`
	Name       string `json:"name"`
	Department string `json:"department"`
	IsAdmin    int    `json:"is_admin"` // 0 = User, 1 = Admin
}

// --- 主要進入點 ---
func main() {
	// 1. 初始化兩個資料庫 (連線 CockroachDB)
	initUserDB()
	initProjectDB()

	// 2. 設定 Gin 路由
	router := gin.Default()

	// --- 靜態檔案 (HTML) ---
	router.GET("/", func(c *gin.Context) { c.File("./login.html") })
	router.GET("/projects", func(c *gin.Context) { c.File("./projects.html") })
	router.GET("/gantt", func(c *gin.Context) { c.File("./gantt.html") })
	router.GET("/admin", func(c *gin.Context) { c.File("./admin.html") })
	router.GET("/login.html", func(c *gin.Context) { c.File("./login.html") })
	router.GET("/projects.html", func(c *gin.Context) { c.File("./projects.html") })
	router.GET("/gantt.html", func(c *gin.Context) { c.File("./gantt.html") })
	router.GET("/admin.html", func(c *gin.Context) { c.File("./admin.html") })

	// --- API 路由 ---
	api := router.Group("/api")
	{
		api.POST("/auth/login", handleLogin)

		projects := api.Group("/projects")
		projects.Use(authMiddleware())
		{
			projects.GET("", handleGetProjects)
			projects.POST("", handleCreateProject) 
			projects.GET("/:project_id", handleGetProjectByID) 
			projects.DELETE("/:project_id", handleDeleteProject)
			projects.GET("/:project_id/tasks", handleGetTasks)
			projects.POST("/:project_id/tasks", handleSaveTasks) 
		}

		admin := api.Group("/admin")
		admin.Use(authMiddleware())
		admin.Use(adminAuthMiddleware())
		{
			admin.GET("/users", handleGetUsers)
			admin.POST("/users", handleCreateUser) 
			admin.DELETE("/users/:id", handleDeleteUser)
			admin.POST("/clear-all-data", handleClearAllData)
		}
	}

	// 4. 啟動伺服器
	log.Println("伺服器啟動於 http://localhost:8080")
	log.Println("【重要】資料庫連線字串請透過環境變數 USER_DB_URL 和 PROJECT_DB_URL 設定。")
	router.Run(":8080")
}

// --- 資料庫初始化 (CockroachDB/PostgreSQL 專用) ---

// 輔助函數：連線到 CockroachDB
func connectDB(envVar string) *sql.DB {
	connStr := os.Getenv(envVar)
	if connStr == "" {
		log.Fatalf("FATAL: 環境變數 %s 未設定，無法連線資料庫。請在 Render 中設定。", envVar)
	}

	// 使用 postgres 驅動
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("無法連線到 CockroachDB (%s): %v", envVar, err)
	}

	// 測試連線
	if err = db.Ping(); err != nil {
		log.Fatalf("無法 Ping CockroachDB (%s): %v", envVar, err)
	}

	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(20)

	log.Printf("成功連線到 CockroachDB: %s", envVar)
	return db
}

func initUserDB() {
	userDB = connectDB("USER_DB_URL") 

	// users 資料表 (使用 SERIAL PRIMARY KEY)
	createUsersTable := `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        department TEXT,
        is_admin INT NOT NULL DEFAULT 0
    );`
	_, err := userDB.Exec(createUsersTable)
	if err != nil {
		log.Fatal("無法建立 users 資料表: ", err)
	}

	// 插入預設帳號
	_, err = userDB.Exec(`
        INSERT INTO users (username, password, name, department, is_admin) 
        VALUES ('admin', 'admin', 'Site Admin', 'IT', 1) 
        ON CONFLICT (username) DO NOTHING;
    `)
	if err != nil {
		log.Println("插入 admin 資料時發生錯誤: ", err)
	}
}

func initProjectDB() {
	projectDB = connectDB("PROJECT_DB_URL") 

	// projects 資料表 (使用 SERIAL PRIMARY KEY)
	createProjectsTable := `
    CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        department TEXT
    );`
	_, err := projectDB.Exec(createProjectsTable)
	if err != nil {
		log.Fatal("無法建立 projects 資料表: ", err)
	}

	// tasks 資料表 (包含 FOREIGN KEY ON DELETE CASCADE)
	createTasksTable := `
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        start TEXT NOT NULL,
        durationdays INTEGER NOT NULL,
        priority INTEGER NOT NULL,
        PRIMARY KEY (id, project_id),
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    );
    `
	_, err = projectDB.Exec(createTasksTable)
	if err != nil {
		log.Fatal("無法建立 tasks 資料表: ", err)
	}
}

// --- API 處理函數 (Handlers) ---

// 處理登入 (使用 $1, $2)
func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的請求"})
		return
	}
	var user User
	err := userDB.QueryRow("SELECT id, username, name, department, is_admin FROM users WHERE username = $1 AND password = $2", req.Username, req.Password).Scan(&user.ID, &user.Username, &user.Name, &user.Department, &user.IsAdmin)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "使用者名稱或密碼錯誤"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "資料庫錯誤: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": user.Username, "user": user})
}

// 處理 "取得所有專案" 
func handleGetProjects(c *gin.Context) {
	rows, err := projectDB.Query("SELECT id, name, department FROM projects")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "無法查詢專案"})
		return
	}
	defer rows.Close()
	projects := []Project{}
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Department); err != nil {
			continue
		}
		projects = append(projects, p)
	}
	c.JSON(http.StatusOK, projects)
}

// 處理 "根據 ID 取得單一專案" (使用 $1)
func handleGetProjectByID(c *gin.Context) {
	projectID := c.Param("project_id")
	var project Project
	err := projectDB.QueryRow("SELECT id, name, department FROM projects WHERE id = $1", projectID).Scan(&project.ID, &project.Name, &project.Department)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "找不到指定的專案 ID: " + projectID})
		return
	}
	if err != nil {
		log.Printf("ERROR: handleGetProjectByID - ProjectID %s: %v", projectID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查詢專案時發生資料庫錯誤"})
		return
	}
	c.JSON(http.StatusOK, project)
}

// 處理 "取得特定專案的任務" (使用 $1)
func handleGetTasks(c *gin.Context) {
	projectID := c.Param("project_id")
	rows, err := projectDB.Query("SELECT id, name, start, durationdays, priority FROM tasks WHERE project_id = $1 ORDER BY id ASC", projectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "無法查詢任務"})
		return
	}
	defer rows.Close()
	tasks := []Task{}
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.Name, &t.Start, &t.DurationDays, &t.Priority); err != nil {
			continue
		}
		tasks = append(tasks, t)
	}
	c.JSON(http.StatusOK, tasks)
}

// 處理 "儲存(覆蓋)特定專案的所有任務" (已新增專案存在性檢查)
func handleSaveTasks(c *gin.Context) {
	projectIDStr := c.Param("project_id")
	projectID, err := strconv.Atoi(projectIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的專案 ID"})
		return
	}

    // --- 檢查專案是否存在 (防止外鍵錯誤) ---
    var existsID int
    err = projectDB.QueryRow("SELECT id FROM projects WHERE id = $1", projectID).Scan(&existsID)
    
    if err == sql.ErrNoRows {
        c.JSON(http.StatusNotFound, gin.H{"error": "專案 ID 不存在，無法儲存任務"})
        return
    }
    if err != nil {
        log.Printf("ERROR: 檢查專案存在性失敗: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "檢查專案存在性時發生資料庫錯誤"})
        return
    }
    // ----------------------------------------

	var tasks []Task
	if err := c.ShouldBindJSON(&tasks); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的任務資料格式"})
		return
	}

	tx, err := projectDB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "無法啟動交易"})
		return
	}
	
	_, err = tx.Exec("DELETE FROM tasks WHERE project_id = $1", projectID)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除舊任務失敗"})
		return
	}
	
	stmt, err := tx.Prepare("INSERT INTO tasks (id, name, start, durationdays, priority, project_id) VALUES ($1, $2, $3, $4, $5, $6)")
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "準備插入任務失敗"})
		return
	}
	defer stmt.Close()
	for _, task := range tasks {
		_, err = stmt.Exec(task.ID, task.Name, task.Start, task.DurationDays, task.Priority, projectID)
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "插入任務時失敗: " + err.Error()})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "提交交易失敗"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// 處理 "建立新專案" (已修復使用 RETURNING ID)
// 處理 "建立新專案" (使用 projectDB) - 最終修正版
func handleCreateProject(c *gin.Context) {
	var req ProjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的請求: " + err.Error()})
		return
	}
	
    var newID int
	// 【修正】: 移除 stmt.Exec 和 LastInsertId，完全使用 QueryRow + RETURNING
	query := "INSERT INTO projects (name, department) VALUES ($1, $2) RETURNING id"
    
    // 使用 QueryRow 執行 INSERT，並將返回的 id 掃描到 newID 變數中
	err := projectDB.QueryRow(query, req.Name, req.Department).Scan(&newID)

	if err != nil {
		log.Printf("ERROR: handleCreateProject 執行失敗: %v", err) // 新增日誌
		c.JSON(http.StatusInternalServerError, gin.H{"error": "資料庫執行失敗: " + err.Error()})
		return
	}
    
	// 成功取得新 ID (此 ID 為 CRDB 分配的唯一 ID)
	newProject := Project{ID: newID, Name: req.Name, Department: req.Department}
	
    // 確認 ID 是有效值後再回傳 (選用，但有助於偵錯)
    log.Printf("INFO: 成功創建專案 ID: %d", newID) 
	c.JSON(http.StatusCreated, newProject)
}

// 處理 "刪除專案" (使用 $1)
func handleDeleteProject(c *gin.Context) {
	projectID := c.Param("project_id")
	_, err := projectDB.Exec("DELETE FROM projects WHERE id = $1", projectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除專案失敗: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// --- 以下為管理員 API Handlers ---

// 處理 "取得所有使用者" 
func handleGetUsers(c *gin.Context) {
	rows, err := userDB.Query("SELECT id, username, name, department, is_admin FROM users")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "無法查詢使用者"})
		return
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Name, &u.Department, &u.IsAdmin); err != nil {
			continue
		}
		users = append(users, u)
	}
	c.JSON(http.StatusOK, users)
}

// 處理 "建立新使用者" (已修復使用 RETURNING ID)
func handleCreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的請求: " + err.Error()})
		return
	}
	
    var newID int
	// 使用 INSERT ... RETURNING id
    query := "INSERT INTO users (username, password, name, department, is_admin) VALUES ($1, $2, $3, $4, $5) RETURNING id"
    
    // 使用 QueryRow 執行 INSERT 並將返回的 id 掃描到 newID 變數中
	err := userDB.QueryRow(query, req.Username, req.Password, req.Name, req.Department, req.IsAdmin).Scan(&newID)

	if err != nil {
		// 檢查唯一性約束錯誤
		if strings.Contains(err.Error(), "duplicate key value") { 
			c.JSON(http.StatusConflict, gin.H{"error": "此使用者名稱已被註冊"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "資料庫執行失敗: " + err.Error()})
		return
	}
    
	newUser := User{ID: newID, Username: req.Username, Name: req.Name, Department: req.Department, IsAdmin: req.IsAdmin}
	c.JSON(http.StatusCreated, newUser)
}

// 處理 "刪除使用者" (使用 $1)
func handleDeleteUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "1" {
		c.JSON(http.StatusForbidden, gin.H{"error": "無法刪除主要的管理員帳號"})
		return
	}
	_, err := userDB.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除使用者失敗: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// 處理 "清除所有資料" 
func handleClearAllData(c *gin.Context) {

	// 1. 清除 Project DB
	projectTx, err := projectDB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "無法啟動 projectDB 交易"})
		return
	}
	
	_, err = projectTx.Exec("DELETE FROM tasks")
	if err != nil {
		projectTx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除 tasks 失敗"})
		return
	}
	
	_, err = projectTx.Exec("DELETE FROM projects")
	if err != nil {
		projectTx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除 projects 失敗"})
		return
	}
	if err := projectTx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "提交 projectDB 交易失敗"})
		return
	}

	// 2. 清除 User DB
	userTx, err := userDB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "無法啟動 userDB 交易"})
		return
	}
	
	_, err = userTx.Exec("DELETE FROM users")
	if err != nil {
		userTx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除 users 失敗"})
		return
	}
	// 重新插入預設的管理員帳號 
	_, err = userTx.Exec(`
        INSERT INTO users (username, password, name, department, is_admin) 
        VALUES ('admin', 'admin', 'Site Admin', 'IT', 1) 
        ON CONFLICT (username) DO NOTHING;
    `)
	if err != nil {
		userTx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重建 admin 失敗"})
		return
	}
	if err := userTx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "提交 userDB 交易失敗"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "所有資料已清除，管理員帳號 'admin' 已保留。"})
}

// --- 認證中間件 (Middleware) ---
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未提供 Token"})
			return
		}
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token 格式錯誤"})
			return
		}
		token := tokenParts[1]
		var is_admin int
		// SQL 語句變更: 使用 $1
		err := userDB.QueryRow("SELECT is_admin FROM users WHERE username = $1", token).Scan(&is_admin)
		if err == sql.ErrNoRows {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token 無效 (使用者不存在)"})
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "資料庫查詢 Token 失敗"})
			return
		}
		c.Set("username", token)
		c.Set("is_admin", is_admin == 1)
		c.Next()
	}
}

func adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, exists := c.Get("is_admin")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "認證狀態遺失"})
			return
		}
		if isAdmin.(bool) == false {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "權限不足 (需要管理員權限)"})
			return
		}
		c.Next()
	}
}