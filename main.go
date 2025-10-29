package main

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite" // 使用 "純 Go" 的 SQLite 驅動
)

// --- 雙資料庫變數 ---
var userDB *sql.DB    // 用於 users 資料表 (user.db)
var projectDB *sql.DB // 用於 projects 和 tasks 資料表 (project.db)

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
	Name       string `json:"name"       binding:"required"`
	Department string `json:"department" binding:"required"`
}
type CreateUserRequest struct {
	Username   string `json:"username"   binding:"required"`
	Password   string `json:"password"   binding:"required"`
	Name       string `json:"name"`
	Department string `json:"department"`
	IsAdmin    int    `json:"is_admin"` // 0 = User, 1 = Admin
}

// --- 主要進入點 ---
func main() {
	// 1. 初始化兩個資料庫
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
			projects.GET("/:project_id", handleGetProjectByID) // 取得單一專案名稱用
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
	log.Println("使用者資料庫: user.db")
	log.Println("專案資料庫: project.db")
	router.Run(":8080")
}

// --- 資料庫初始化 ---
func initUserDB() {
	var err error
	userDB, err = sql.Open("sqlite", "./user.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal("無法開啟 user.db: ", err)
	}

	// users 資料表
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		name TEXT,
		department TEXT,
		is_admin INTEGER NOT NULL DEFAULT 0
	);`
	_, err = userDB.Exec(createUsersTable)
	if err != nil {
		log.Fatal("無法建立 users 資料表: ", err)
	}

	// 插入預設帳號 (僅 admin)
	_, err = userDB.Exec(`INSERT OR IGNORE INTO users (id, username, password, name, department, is_admin) VALUES 
		(1, 'admin', 'admin', 'Site Admin', 'IT', 1);
	`)
	if err != nil {
		log.Println("插入 admin 資料時發生錯誤: ", err)
	}
	// 移除 rd/pm 預設插入
}

func initProjectDB() {
	var err error
	// 啟用外鍵支援
	projectDB, err = sql.Open("sqlite", "./project.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal("無法開啟 project.db: ", err)
	}

	// projects 資料表
	createProjectsTable := `
	CREATE TABLE IF NOT EXISTS projects (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		department TEXT
	);`
	_, err = projectDB.Exec(createProjectsTable)
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

	// 移除預設專案和任務插入
}

// --- API 處理函數 (Handlers) ---

// 處理登入 (使用 userDB)
func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": "無效的請求"}); return }
	var user User
	err := userDB.QueryRow("SELECT id, username, name, department, is_admin FROM users WHERE username = ? AND password = ?", req.Username, req.Password).Scan(&user.ID, &user.Username, &user.Name, &user.Department, &user.IsAdmin)
	if err == sql.ErrNoRows { c.JSON(http.StatusUnauthorized, gin.H{"error": "使用者名稱或密碼錯誤"}); return }
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "資料庫錯誤: " + err.Error()}); return }
	c.JSON(http.StatusOK, gin.H{"token": user.Username, "user": user})
}

// 處理 "取得所有專案" (使用 projectDB)
func handleGetProjects(c *gin.Context) {
	rows, err := projectDB.Query("SELECT id, name, department FROM projects")
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "無法查詢專案"}); return }
	defer rows.Close()
	projects := []Project{}
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Department); err != nil { continue }
		projects = append(projects, p)
	}
	c.JSON(http.StatusOK, projects)
}

// 處理 "根據 ID 取得單一專案" (使用 projectDB)
func handleGetProjectByID(c *gin.Context) {
	projectID := c.Param("project_id")
	var project Project
	err := projectDB.QueryRow("SELECT id, name, department FROM projects WHERE id = ?", projectID).Scan(&project.ID, &project.Name, &project.Department)

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


// 處理 "取得特定專案的任務" (使用 projectDB)
func handleGetTasks(c *gin.Context) {
	projectID := c.Param("project_id")
	rows, err := projectDB.Query("SELECT id, name, start, durationdays, priority FROM tasks WHERE project_id = ? ORDER BY id ASC", projectID)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "無法查詢任務"}); return }
	defer rows.Close()
	tasks := []Task{}
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.Name, &t.Start, &t.DurationDays, &t.Priority); err != nil { continue }
		tasks = append(tasks, t)
	}
	c.JSON(http.StatusOK, tasks)
}

// 處理 "儲存(覆蓋)特定專案的所有任務" (使用 projectDB)
func handleSaveTasks(c *gin.Context) {
	projectIDStr := c.Param("project_id")
	projectID, err := strconv.Atoi(projectIDStr)
	if err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": "無效的專案 ID"}); return }
	var tasks []Task
	if err := c.ShouldBindJSON(&tasks); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": "無效的任務資料格式"}); return }
	tx, err := projectDB.Begin()
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "無法啟動交易"}); return }
	_, err = tx.Exec("DELETE FROM tasks WHERE project_id = ?", projectID)
	if err != nil { tx.Rollback(); c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除舊任務失敗"}); return }
	stmt, err := tx.Prepare("INSERT INTO tasks (id, name, start, durationdays, priority, project_id) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil { tx.Rollback(); c.JSON(http.StatusInternalServerError, gin.H{"error": "準備插入任務失敗"}); return }
	defer stmt.Close()
	for _, task := range tasks {
		_, err = stmt.Exec(task.ID, task.Name, task.Start, task.DurationDays, task.Priority, projectID)
		if err != nil { tx.Rollback(); c.JSON(http.StatusInternalServerError, gin.H{"error": "插入任務時失敗: " + err.Error()}); return }
	}
	if err := tx.Commit(); err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "提交交易失敗"}); return }
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// 處理 "建立新專案" (使用 projectDB)
func handleCreateProject(c *gin.Context) {
	var req ProjectRequest
	if err := c.ShouldBindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": "無效的請求: " + err.Error()}); return }
	stmt, err := projectDB.Prepare("INSERT INTO projects (name, department) VALUES (?, ?)")
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "資料庫準備失敗: " + err.Error()}); return }
	defer stmt.Close()
	result, err := stmt.Exec(req.Name, req.Department)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "資料庫執行失敗: " + err.Error()}); return }
	newID, err := result.LastInsertId()
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "無法取得新專案 ID: " + err.Error()}); return }
	newProject := Project{ID: int(newID), Name: req.Name, Department: req.Department}
	c.JSON(http.StatusCreated, newProject)
}

// 處理 "刪除專案" (使用 projectDB)
func handleDeleteProject(c *gin.Context) {
	projectID := c.Param("project_id")
	_, err := projectDB.Exec("DELETE FROM projects WHERE id = ?", projectID)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除專案失敗: " + err.Error()}); return }
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// --- 以下為管理員 API Handlers ---

// 處理 "取得所有使用者" (使用 userDB)
func handleGetUsers(c *gin.Context) {
	rows, err := userDB.Query("SELECT id, username, name, department, is_admin FROM users")
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "無法查詢使用者"}); return }
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Name, &u.Department, &u.IsAdmin); err != nil { continue }
		users = append(users, u)
	}
	c.JSON(http.StatusOK, users)
}

// 處理 "建立新使用者" (使用 userDB)
func handleCreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": "無效的請求: " + err.Error()}); return }
	stmt, err := userDB.Prepare("INSERT INTO users (username, password, name, department, is_admin) VALUES (?, ?, ?, ?, ?)")
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "資料庫準備失敗: " + err.Error()}); return }
	defer stmt.Close()
	result, err := stmt.Exec(req.Username, req.Password, req.Name, req.Department, req.IsAdmin)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			c.JSON(http.StatusConflict, gin.H{"error": "此使用者名稱已被註冊"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "資料庫執行失敗: " + err.Error()}); return
	}
	newID, err := result.LastInsertId()
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "無法取得新使用者 ID: " + err.Error()}); return }
	newUser := User{ID: int(newID), Username: req.Username, Name: req.Name, Department: req.Department, IsAdmin: req.IsAdmin}
	c.JSON(http.StatusCreated, newUser)
}

// 處理 "刪除使用者" (使用 userDB)
func handleDeleteUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "1" { c.JSON(http.StatusForbidden, gin.H{"error": "無法刪除主要的管理員帳號"}); return }
	_, err := userDB.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除使用者失敗: " + err.Error()}); return }
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// 處理 "清除所有資料" (使用 userDB 和 projectDB)
func handleClearAllData(c *gin.Context) {
	
	// 1. 清除 Project DB
	projectTx, err := projectDB.Begin()
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "無法啟動 projectDB 交易"}); return }
	_, err = projectTx.Exec("DELETE FROM tasks")
	if err != nil { projectTx.Rollback(); c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除 tasks 失敗"}); return }
	_, err = projectTx.Exec("DELETE FROM projects")
	if err != nil { projectTx.Rollback(); c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除 projects 失敗"}); return }
	if err := projectTx.Commit(); err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "提交 projectDB 交易失敗"}); return }

	// 2. 清除 User DB
	userTx, err := userDB.Begin()
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "無法啟動 userDB 交易"}); return }
	_, err = userTx.Exec("DELETE FROM users")
	if err != nil { userTx.Rollback(); c.JSON(http.StatusInternalServerError, gin.H{"error": "刪除 users 失敗"}); return }
	// 重新插入預設的管理員帳號
	_, err = userTx.Exec(`INSERT OR IGNORE INTO users (id, username, password, name, department, is_admin) VALUES 
		(1, 'admin', 'admin', 'Site Admin', 'IT', 1)
	`)
	if err != nil { userTx.Rollback(); c.JSON(http.StatusInternalServerError, gin.H{"error": "重建 admin 失敗"}); return }
	if err := userTx.Commit(); err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "提交 userDB 交易失敗"}); return }

	c.JSON(http.StatusOK, gin.H{"status": "所有資料已清除，管理員帳號 'admin' 已保留。"})
}

// --- 認證中間件 (Middleware) ---
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" { c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未提供 Token"}); return }
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" { c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token 格式錯誤"}); return }
		token := tokenParts[1]
		var is_admin int
		err := userDB.QueryRow("SELECT is_admin FROM users WHERE username = ?", token).Scan(&is_admin)
		if err == sql.ErrNoRows { c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token 無效 (使用者不存在)"}); return }
		if err != nil { c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "資料庫查詢 Token 失敗"}); return }
		c.Set("username", token)
		c.Set("is_admin", is_admin == 1)
		c.Next()
	}
}

func adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, exists := c.Get("is_admin")
		if !exists { c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "認證狀態遺失"}); return }
		if isAdmin.(bool) == false { c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "權限不足 (需要管理員權限)"}); return }
		c.Next()
	}
}