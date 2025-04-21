package services

import (
	"context"
	"fmt"
	"log"
	services "modsecurity-rules-db/services/model"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Neo4jService struct {
	Driver neo4j.DriverWithContext
	Limit  int
}

func Retry(attempts int, sleep time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		fmt.Printf("Retry %d/%d failed: %v\n", i+1, attempts, err)
		time.Sleep(sleep)
		sleep *= 2 // backoff exponencial
	}
	return fmt.Errorf("after %d attempts, last error: %w", attempts, err)
}

func NewNeo4jService(uri, username, password string) (*Neo4jService, error) {
	var driver neo4j.DriverWithContext
	err := Retry(5, 2*time.Second, func() error {
		var err error
		driver, err = neo4j.NewDriverWithContext(
			uri,
			neo4j.BasicAuth(username, password, ""),
		)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return driver.VerifyConnectivity(ctx)
	})
	return &Neo4jService{Driver: driver}, err
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
