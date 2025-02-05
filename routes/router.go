package routes

import (
	"modsecurity-rules-db/controllers"
	"net/http"

	"github.com/gorilla/mux"
)

func RegisterRoutes(router *mux.Router, ModsecurityRulesController *controllers.ModsecurityRulesController) {
	router.HandleFunc("/save-modsecurity-rules", func(w http.ResponseWriter, r *http.Request) {
		err := ModsecurityRulesController.LoadModsecurityRules(w, r)
		if err != nil {
			http.Error(w, "Failed to save modsecurity rules", http.StatusInternalServerError)
		}
	}).Methods("GET")
}
