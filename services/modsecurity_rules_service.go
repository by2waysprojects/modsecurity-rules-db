package services

type ModsecurityRulesService struct {
	Neo4jService       *Neo4jService
	GithubRulesService *GithubRulesService
}

func NewModsecurityRulesService(dbService *Neo4jService, githubRulesService *GithubRulesService) *ModsecurityRulesService {
	return &ModsecurityRulesService{Neo4jService: dbService, GithubRulesService: githubRulesService}
}

func (s *ModsecurityRulesService) SaveGithubModsecurityRules(limit int) error {
	modsecurityRules, err := s.GithubRulesService.FetchAllModsecurityRules(limit)
	if err != nil {
		return err
	}

	if err := s.Neo4jService.SaveModsecurityRules(modsecurityRules); err != nil {
		return err
	}
	return nil
}
