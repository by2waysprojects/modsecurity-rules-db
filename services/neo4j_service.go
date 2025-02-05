package services

import (
	"context"
	"log"
	services "modsecurity-rules-db/services/model"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Neo4jService struct {
	Driver neo4j.DriverWithContext
	Limit  int
}

func NewNeo4jService(uri, username, password string) *Neo4jService {
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		log.Fatalf("Failed to create Neo4j driver: %v", err)
	}
	return &Neo4jService{Driver: driver}
}

func (s *Neo4jService) Close() {
	s.Driver.Close(context.Background())
}

func (s *Neo4jService) SaveModsecurityRules(modsecurityRules map[string]string) error {
	ctx := context.Background()
	session := s.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	for name, rule := range modsecurityRules {
		modsecurityRule := services.ModSecurityRuleNeo4j{ID: name, Rule: rule, Action: services.Alert}
		query := `
			CREATE (i:ModSecRule {
				id: $id,
				rule: $rule,
				action: $action
			})
		`
		// Execute the query
		_, err := session.Run(ctx, query, map[string]interface{}{
			"id":     string(modsecurityRule.ID),
			"rule":   string(modsecurityRule.Rule),
			"action": string(modsecurityRule.Action),
		})
		if err != nil {
			log.Printf("Error inserting record from rule %s: %v", rule, err)
		}
	}

	return nil
}
