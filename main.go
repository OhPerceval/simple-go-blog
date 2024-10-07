package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// Configuration de la base de données
const (
	DB_USER     = "root"
	DB_PASSWORD = "root"
	DB_NAME     = "blogdb"
)

// Définir le type Article
type Article struct {
	ID       int           `json:"id"`
	Titre    string        `json:"titre"`
	Contenu  template.HTML `json:"contenu"`
	Tags     string
	Auteur   string
	Likes    int
	Dislikes int
}

// Définir le type Utilisateur
type Utilisateur struct {
	ID         int    `json:"id"`
	Nom        string `json:"nom"`
	Email      string
	MotDePasse string
	Grade      string `json:"grade"`
}

// Créer une session
var store = sessions.NewCookieStore([]byte("secret-key"))

var templates *template.Template

// Connexion à la base de données
var db *sql.DB

// Fonctions pour la pagination
func sub(a, b int) int {
	return a - b
}

func add(a, b int) int {
	return a + b
}

func mul(a, b int) int {
	return a * b
}

func split(s string) []string {
	return strings.Split(s, ",")
}

func trim(s string) string {
	return strings.TrimSpace(s)
}

func safeHTML(html string) template.HTML {
	return template.HTML(html)
}

func truncateHTML(html string, maxLength int) string {

	var truncated strings.Builder
	length := 0
	inTag := false

	for i := 0; i < len(html); i++ {
		char := html[i]

		if char == '<' {
			inTag = true
		} else if char == '>' {
			inTag = false
		}

		if inTag {
			truncated.WriteByte(char)
			continue
		}

		if length < maxLength {
			truncated.WriteByte(char)
			length++
		} else {
			break
		}
	}

	if length >= maxLength {
		truncated.WriteString("...")
	}

	return truncated.String()
}

func main() {
	var err error
	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(localhost:3306)/%s", DB_USER, DB_PASSWORD, DB_NAME))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Initialisation des templates
	templates = template.Must(template.New("").Funcs(template.FuncMap{
		"sub":      sub,
		"add":      add,
		"mul":      mul,
		"split":    split,
		"trim":     trim,
		"safeHTML": safeHTML,
	}).ParseGlob("templates/*.html"))

	// Configurer les routes
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/article/", articleHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/comment", commentHandler)
	http.HandleFunc("/comment/edit", editCommentHandler)
	http.HandleFunc("/comment/delete", deleteCommentHandler)
	http.HandleFunc("/article/react", reactHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/admin/article", articleHandlerAdmin)
	http.HandleFunc("/admin/user", editUserGradeHandler)
	http.HandleFunc("/admin/users", usersHandler)

	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Handler pour l'index
func indexHandler(w http.ResponseWriter, r *http.Request) {

	page := r.URL.Query().Get("page")
	if page == "" {
		page = "1"
	}
	pageNum, err := strconv.Atoi(page)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des articles", http.StatusBadRequest)
		return
	}
	offset := (pageNum - 1) * 2

	rows, err := db.Query("SELECT a.id, a.titre, a.contenu, u.nom FROM articles a JOIN utilisateurs u ON a.auteur_id = u.id ORDER BY a.created_at DESC LIMIT 2 OFFSET ?", offset)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des articles", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var articles []Article
	for rows.Next() {
		var article Article
		if err := rows.Scan(&article.ID, &article.Titre, &article.Contenu, &article.Auteur); err != nil {
			http.Error(w, "Erreur lors du scan des articles", http.StatusInternalServerError)
			return
		}

		truncatedContent := truncateHTML(string(article.Contenu), 100)
		article.Contenu = safeHTML(truncatedContent)

		articles = append(articles, article)
	}

	var totalArticles int
	err = db.QueryRow("SELECT COUNT(*) FROM articles").Scan(&totalArticles)
	if err != nil {
		http.Error(w, "Erreur lors du comptage des articles", http.StatusInternalServerError)
		return
	}

	session, err := store.Get(r, "session")
	if err != nil {
		http.Error(w, "Erreur lors de la récupération de la session", http.StatusInternalServerError)
		return
	}

	connected := session.Values["user_id"] != nil
	var username string
	var role string
	if connected {
		if val, ok := session.Values["username"].(string); ok {
			username = val
		}
		if val, ok := session.Values["user_grade"].(string); ok {
			role = val
		}
	}

	var errorMessage string
	if val, ok := session.Values["error"].(string); ok {
		errorMessage = val
		delete(session.Values, "error")
		session.Save(r, w)
	}

	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		templates.ExecuteTemplate(w, "partials/articles.html", map[string]interface{}{
			"Articles":  articles,
			"Connected": connected,
			"Username":  username,
			"Role":      role,
		})
		return
	}

	templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Articles":      articles,
		"Page":          pageNum,
		"Connected":     connected,
		"Username":      username,
		"Role":          role,
		"TotalArticles": totalArticles,
		"Error":         errorMessage,
	})
}

// Handler pour afficher un article
func articleHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/article/"):]

	var article Article
	err := db.QueryRow("SELECT id, titre, contenu, likes, dislikes FROM articles WHERE id = ?", id).
		Scan(&article.ID, &article.Titre, &article.Contenu, &article.Likes, &article.Dislikes)
	if err != nil {
		http.Error(w, "Article non trouvé", http.StatusNotFound)
		return
	}

	// Convertir le contenu en template.HTML pour permettre l'affichage en tant que HTML
	article.Contenu = template.HTML(article.Contenu)

	rows, err := db.Query("SELECT c.id, c.contenu, c.utilisateur_id, u.nom FROM commentaires c JOIN utilisateurs u ON c.utilisateur_id = u.id WHERE c.article_id = ?", article.ID)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des commentaires", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var comments []struct {
		ID      int
		Content string
		UserID  int
		Author  string
	}
	for rows.Next() {
		var comment struct {
			ID      int
			Content string
			UserID  int
			Author  string
		}
		if err := rows.Scan(&comment.ID, &comment.Content, &comment.UserID, &comment.Author); err != nil {
			http.Error(w, "Erreur lors du scan des commentaires", http.StatusInternalServerError)
			return
		}
		comments = append(comments, comment)
	}

	session, err := store.Get(r, "session")
	if err != nil {
		http.Error(w, "Erreur lors de la récupération de la session", http.StatusInternalServerError)
		return
	}

	connected := session.Values["user_id"] != nil
	var username string
	var role string
	var userID int
	if connected {
		if val, ok := session.Values["username"].(string); ok {
			username = val
		}
		if val, ok := session.Values["user_grade"].(string); ok {
			role = val
		}
		if val, ok := session.Values["user_id"].(int); ok {
			userID = val
		}
	}

	// Passer l'article, les commentaires et les informations de session au template
	templates.ExecuteTemplate(w, "article.html", map[string]interface{}{
		"Article":   article,
		"Comments":  comments,
		"Connected": connected,
		"Username":  username,
		"Role":      role,
		"UserID":    userID,
	})
}

func isValidPassword(password string) bool {
	var (
		length  = len(password) >= 8
		upper   = regexp.MustCompile(`[A-Z]`).MatchString(password)
		special = regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)
	)

	return length && upper && special
}

// Handler pour la connexion
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		motDePasse := r.FormValue("mot_de_passe")
		redirectURL := r.FormValue("redirect")

		var hashedPassword string
		var userID int
		var username string
		var role string

		err := db.QueryRow("SELECT id, nom, mot_de_passe, grade FROM utilisateurs WHERE email = ?", email).Scan(&userID, &username, &hashedPassword, &role)
		if err != nil {

			session, _ := store.Get(r, "session")
			session.Values["error"] = "Adresse email incorrecte."
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Vérification du mot de passe
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(motDePasse))
		if err != nil {

			session, _ := store.Get(r, "session")
			session.Values["error"] = "Mot de passe incorrect."
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Créer une session pour l'utilisateur
		session, _ := store.Get(r, "session")
		session.Values["user_id"] = userID
		session.Values["username"] = username
		session.Values["user_grade"] = role

		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Erreur lors de l'enregistrement de la session", http.StatusInternalServerError)
			return
		}

		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		return
	}

	templates.ExecuteTemplate(w, "index.html", nil)
}

// Handler pour l'inscription
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		nom := r.FormValue("nom")
		email := r.FormValue("email")
		motDePasse := r.FormValue("mot_de_passe")
		redirectURL := r.FormValue("redirect")

		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM utilisateurs WHERE nom = ? OR email = ?", nom, email).Scan(&exists)
		if err != nil {
			http.Error(w, "Erreur lors de la vérification des utilisateurs", http.StatusInternalServerError)
			return
		}

		if exists > 0 {

			session, _ := store.Get(r, "session")
			session.Values["error"] = "Le pseudo ou l'adresse email est déjà utilisé."
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Hachage du mot de passe
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(motDePasse), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Erreur lors de l'inscription", http.StatusInternalServerError)
			return
		}

		// Inscription de l'utilisateur
		_, err = db.Exec("INSERT INTO utilisateurs (nom, email, mot_de_passe) VALUES (?, ?, ?)", nom, email, hashedPassword)
		if err != nil {
			http.Error(w, "Erreur lors de l'inscription", http.StatusInternalServerError)
			return
		}

		// Récupérer l'ID de l'utilisateur pour la session
		var userID int
		err = db.QueryRow("SELECT id FROM utilisateurs WHERE email = ?", email).Scan(&userID)
		if err != nil {
			http.Error(w, "Erreur lors de la récupération de l'utilisateur", http.StatusInternalServerError)
			return
		}

		session, _ := store.Get(r, "session")
		session.Values["user_id"] = userID
		session.Values["user_grade"] = "user"
		session.Values["username"] = nom
		session.Save(r, w)

		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		return
	}

	templates.ExecuteTemplate(w, "index.html", nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Values["user_id"] = nil
	session.Values["username"] = nil
	session.Save(r, w)

	redirectURL := r.URL.Query().Get("redirect") // Récupérer l'URL de redirection
	if redirectURL != "" {
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// Handler pour les commentaires
func commentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		articleID := r.FormValue("article_id")
		contenu := r.FormValue("contenu")

		session, _ := store.Get(r, "session")
		userID := session.Values["user_id"]

		if userID == nil {
			http.Error(w, "Vous devez être connecté pour commenter", http.StatusUnauthorized)
			return
		}

		_, err := db.Exec("INSERT INTO commentaires (article_id, utilisateur_id, contenu) VALUES (?, ?, ?)", articleID, userID, contenu)
		if err != nil {
			http.Error(w, "Erreur lors de l'ajout du commentaire", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/article/%s", articleID), http.StatusSeeOther)
		return
	}
}

// Handler pour modifier un commentaire
// Handler pour modifier un commentaire
func editCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		commentID := r.FormValue("comment_id")
		contenu := r.FormValue("contenu")

		session, _ := store.Get(r, "session")
		userID := session.Values["user_id"]

		if userID == nil {
			http.Error(w, "Vous devez être connecté pour modifier un commentaire", http.StatusUnauthorized)
			return
		}

		// Vérifier si l'utilisateur est l'auteur du commentaire ou un admin
		var authorID int
		err := db.QueryRow("SELECT utilisateur_id FROM commentaires WHERE id = ?", commentID).Scan(&authorID)
		if err != nil {
			http.Error(w, "Commentaire non trouvé", http.StatusNotFound)
			return
		}

		// Récupérer le rôle de l'utilisateur
		var userRole string
		err = db.QueryRow("SELECT grade FROM utilisateurs WHERE id = ?", userID).Scan(&userRole)
		if err != nil {
			http.Error(w, "Erreur lors de la récupération des informations de l'utilisateur", http.StatusInternalServerError)
			return
		}

		if authorID != userID.(int) && userRole != "admin" {
			http.Error(w, "Vous n'êtes pas autorisé à modifier ce commentaire", http.StatusForbidden)
			return
		}

		// Mettre à jour le commentaire avec la date de modification et l'utilisateur qui l'a modifié
		_, err = db.Exec("UPDATE commentaires SET contenu = ?, date_modification = NOW(), modifie_par = ? WHERE id = ?", contenu, userID, commentID)
		if err != nil {
			http.Error(w, "Erreur lors de la mise à jour du commentaire", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		return
	}
}

// Handler pour supprimer un commentaire
func deleteCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		commentID := r.FormValue("comment_id")

		session, _ := store.Get(r, "session")
		userID := session.Values["user_id"]

		if userID == nil {
			http.Error(w, "Vous devez être connecté pour supprimer un commentaire", http.StatusUnauthorized)
			return
		}

		// Vérifier si l'utilisateur est l'auteur du commentaire ou un admin
		var authorID int
		err := db.QueryRow("SELECT utilisateur_id FROM commentaires WHERE id = ?", commentID).Scan(&authorID)
		if err != nil {
			http.Error(w, "Commentaire non trouvé", http.StatusNotFound)
			return
		}

		// Récupérer le rôle de l'utilisateur
		var userRole string
		err = db.QueryRow("SELECT grade FROM utilisateurs WHERE id = ?", userID).Scan(&userRole)
		if err != nil {
			http.Error(w, "Erreur lors de la récupération des informations de l'utilisateur", http.StatusInternalServerError)
			return
		}

		if authorID != userID.(int) && userRole != "admin" {
			http.Error(w, "Vous n'êtes pas autorisé à supprimer ce commentaire", http.StatusForbidden)
			return
		}

		_, err = db.Exec("DELETE FROM commentaires WHERE id = ?", commentID)
		if err != nil {
			http.Error(w, "Erreur lors de la suppression du commentaire", http.StatusInternalServerError)
			return
		}

		// Réponse JSON pour indiquer que la suppression a réussi
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Commentaire supprimé avec succès"))
		return
	}
	http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
}

func reactToArticleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	articleID := r.FormValue("article_id")
	reaction := r.FormValue("reaction")

	if reaction == "like" {
		_, err := db.Exec("UPDATE articles SET likes = likes + 1 WHERE id = ?", articleID)
		if err != nil {
			http.Error(w, "Erreur lors de la mise à jour des likes", http.StatusInternalServerError)
			return
		}
	} else if reaction == "dislike" {
		_, err := db.Exec("UPDATE articles SET dislikes = dislikes + 1 WHERE id = ?", articleID)
		if err != nil {
			http.Error(w, "Erreur lors de la mise à jour des dislikes", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/article/"+articleID, http.StatusSeeOther)
}

func reactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Récupérer l'ID de l'article et la réaction
	articleID := r.FormValue("article_id")
	reaction := r.FormValue("reaction")

	// Vérifier si l'utilisateur est connecté
	session, err := store.Get(r, "session")
	if err != nil {
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["user_id"].(int)
	if !ok {
		http.Error(w, "Vous devez être connecté pour réagir", http.StatusUnauthorized)
		return
	}

	// Vérifier si l'utilisateur a déjà réagi à cet article
	var existingReaction string
	err = db.QueryRow("SELECT reaction FROM reactions WHERE article_id = ? AND user_id = ?", articleID, userID).Scan(&existingReaction)

	if err == nil {
		// Si une réaction existe déjà, renvoyer une réponse JSON avec un statut d'erreur
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "Vous avez déjà réagi à cet article."}`))
		return
	} else if err != sql.ErrNoRows {
		// Autre erreur de requête SQL
		http.Error(w, "Erreur lors de la vérification des réactions", http.StatusInternalServerError)
		return
	}

	// Ajouter la nouvelle réaction (si elle n'existait pas)
	_, err = db.Exec("INSERT INTO reactions (article_id, user_id, reaction) VALUES (?, ?, ?)", articleID, userID, reaction)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout de la réaction", http.StatusInternalServerError)
		return
	}

	// Mettre à jour les compteurs de likes ou dislikes dans la table des articles
	var query string
	if reaction == "like" {
		query = "UPDATE articles SET likes = likes + 1 WHERE id = ?"
	} else if reaction == "dislike" {
		query = "UPDATE articles SET dislikes = dislikes + 1 WHERE id = ?"
	}

	_, err = db.Exec(query, articleID)
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour des réactions", http.StatusInternalServerError)
		return
	}

	// Récupérer les nouveaux compteurs de likes et dislikes
	var likes, dislikes int
	err = db.QueryRow("SELECT likes, dislikes FROM articles WHERE id = ?", articleID).Scan(&likes, &dislikes)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des likes/dislikes", http.StatusInternalServerError)
		return
	}

	// Renvoyer une réponse JSON avec les nouveaux compteurs
	response := map[string]int{
		"likes":    likes,
		"dislikes": dislikes,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Handler principal pour la page admin
// Handler pour la route principale de l'admin
func adminHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil || session.Values["user_grade"] != "admin" {
		http.Error(w, "Accès refusé", http.StatusForbidden)
		return
	}

	// Rendre le template admin.html pour les requêtes GET sans paramètres
	if r.Method == http.MethodGet && r.URL.Query().Get("ajax") == "" {
		templates.ExecuteTemplate(w, "admin.html", nil)
		return
	}

	// Si la requête est en AJAX pour charger les articles et utilisateurs
	if r.Method == http.MethodGet && r.URL.Query().Get("ajax") == "true" {
		// Charger les articles
		rows, err := db.Query("SELECT id, titre, contenu FROM articles")
		if err != nil {
			http.Error(w, "Erreur lors de la récupération des articles", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var articles []Article
		for rows.Next() {
			var article Article
			if err := rows.Scan(&article.ID, &article.Titre, &article.Contenu); err != nil {
				http.Error(w, "Erreur lors du scan des articles", http.StatusInternalServerError)
				return
			}
			articles = append(articles, article)
		}

		// Charger les utilisateurs
		userRows, err := db.Query("SELECT id, nom, grade FROM utilisateurs")
		if err != nil {
			http.Error(w, "Erreur lors de la récupération des utilisateurs", http.StatusInternalServerError)
			return
		}
		defer userRows.Close()

		var utilisateurs []Utilisateur
		for userRows.Next() {
			var utilisateur Utilisateur
			if err := userRows.Scan(&utilisateur.ID, &utilisateur.Nom, &utilisateur.Grade); err != nil {
				http.Error(w, "Erreur lors du scan des utilisateurs", http.StatusInternalServerError)
				return
			}
			utilisateurs = append(utilisateurs, utilisateur)
		}

		// Renvoyer les articles et utilisateurs au format JSON
		response := map[string]interface{}{
			"Articles":     articles,
			"Utilisateurs": utilisateurs,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Gérer les méthodes non autorisées
	http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
}

// Handler pour gérer la création, modification, et suppression d'articles
func articleHandlerAdmin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		// Création d'un nouvel article
		var article Article
		err := json.NewDecoder(r.Body).Decode(&article)
		if err != nil {
			http.Error(w, "Erreur lors de la lecture des données", http.StatusBadRequest)
			return
		}

		// Vérifiez ici que le contenu est bien en format HTML avant de l'insérer
		log.Printf("Création d'un nouvel article avec titre: %s et contenu: %s\n", article.Titre, article.Contenu)

		_, err = db.Exec("INSERT INTO articles (titre, contenu) VALUES (?, ?)", article.Titre, article.Contenu)
		if err != nil {
			http.Error(w, "Erreur lors de la création de l'article", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated) // Indique que l'article a été créé

	case http.MethodPut:
		var article Article
		err := json.NewDecoder(r.Body).Decode(&article)
		if err != nil {
			http.Error(w, "Erreur lors de la lecture des données: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Log des données décodées pour vérifier
		log.Printf("Mise à jour de l'article: %+v\n", article)

		// Enregistrer le contenu en tant que HTML
		_, err = db.Exec("UPDATE articles SET titre = ?, contenu = ? WHERE id = ?", article.Titre, article.Contenu, article.ID)
		if err != nil {
			http.Error(w, "Erreur lors de l'édition de l'article", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK) // Indique que l'article a été modifié

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "ID de l'article manquant", http.StatusBadRequest)
			return
		}

		// Supprimez d'abord les commentaires associés
		_, err := db.Exec("DELETE FROM commentaires WHERE article_id = ?", id)
		if err != nil {
			log.Printf("Erreur lors de la suppression des commentaires: %v\n", err)
			http.Error(w, "Erreur lors de la suppression des commentaires", http.StatusInternalServerError)
			return
		}

		// Supprimez ensuite les réactions associées
		_, err = db.Exec("DELETE FROM reactions WHERE article_id = ?", id)
		if err != nil {
			log.Printf("Erreur lors de la suppression des réactions: %v\n", err)
			http.Error(w, "Erreur lors de la suppression des réactions", http.StatusInternalServerError)
			return
		}

		// Maintenant, supprimez l'article
		_, err = db.Exec("DELETE FROM articles WHERE id = ?", id)
		if err != nil {
			log.Printf("Erreur lors de la suppression de l'article: %v\n", err)
			http.Error(w, "Erreur lors de la suppression de l'article", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent) // Indique que l'article a été supprimé

	case http.MethodGet:
		// Récupérer un article spécifique
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "ID de l'article manquant", http.StatusBadRequest)
			return
		}

		var article Article
		err := db.QueryRow("SELECT id, titre, contenu FROM articles WHERE id = ?", id).Scan(&article.ID, &article.Titre, &article.Contenu)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Article non trouvé", http.StatusNotFound)
			} else {
				http.Error(w, "Erreur lors de la récupération de l'article", http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(article)
		return

	default:
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
	}
}

func editUserGradeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var utilisateur Utilisateur
		if err := json.NewDecoder(r.Body).Decode(&utilisateur); err != nil {
			log.Printf("Erreur lors de la décodage de l'utilisateur: %v", err)
			http.Error(w, "Erreur lors de la décodage de l'utilisateur", http.StatusBadRequest)
			return
		}

		log.Printf("Utilisateur reçu: %+v", utilisateur) // Log de l'utilisateur reçu

		_, err := db.Exec("UPDATE utilisateurs SET grade = ? WHERE id = ?", utilisateur.Grade, utilisateur.ID)
		if err != nil {
			http.Error(w, "Erreur lors de la mise à jour du grade", http.StatusInternalServerError)
			return
		}

		// Renvoyer l'utilisateur mis à jour
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(utilisateur)
	}
}

// Handler pour récupérer la liste des utilisateurs
func usersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, nom, grade FROM utilisateurs")
		if err != nil {
			http.Error(w, "Erreur lors de la récupération des utilisateurs", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var utilisateurs []Utilisateur
		for rows.Next() {
			var utilisateur Utilisateur
			if err := rows.Scan(&utilisateur.ID, &utilisateur.Nom, &utilisateur.Grade); err != nil {
				http.Error(w, "Erreur lors de la lecture des utilisateurs", http.StatusInternalServerError)
				return
			}
			utilisateurs = append(utilisateurs, utilisateur)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(utilisateurs)
	}
}
