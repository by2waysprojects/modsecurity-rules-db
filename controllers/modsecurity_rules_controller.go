package controllers

import (
	"fmt"
	"log"
	"modsecurity-rules-db/services"
	"net/http"
	"strconv"
)

type ModsecurityRulesController struct {
	modsecurityRulesService *services.ModsecurityRulesService
}

func NewModsecurityRulesController(modsecurityRulesService *services.ModsecurityRulesService) *ModsecurityRulesController {
	return &ModsecurityRulesController{modsecurityRulesService: modsecurityRulesService}
}

func (mc *ModsecurityRulesController) LoadModsecurityRules(w http.ResponseWriter, r *http.Request) error {
	log.Println("Saving all rules...")

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 {
		limit = 10000
	}

	log.Printf("Loading limit %d", limit)

	err := mc.modsecurityRulesService.SaveGithubModsecurityRules(limit)
	if err != nil {
		http.Error(w, "Failed saving rules", http.StatusInternalServerError)
		return err
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "All rules are correctly saved")
	return nil
}
