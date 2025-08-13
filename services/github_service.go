package services

import (
	"bufio"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"strings"
)

const baseURL = "https://raw.githubusercontent.com/coreruleset/coreruleset/refs/heads/main/rules/"

var msgRegex = regexp.MustCompile(`msg:'([^']+)'`)

var ruleFiles = []string{
	"REQUEST-901-INITIALIZATION.conf",
	"REQUEST-905-COMMON-EXCEPTIONS.conf",
	"REQUEST-911-METHOD-ENFORCEMENT.conf",
	"REQUEST-913-SCANNER-DETECTION.conf",
	"REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
	"REQUEST-921-PROTOCOL-ATTACK.conf",
	"REQUEST-930-APPLICATION-ATTACK-LFI.conf",
	"REQUEST-931-APPLICATION-ATTACK-RFI.conf",
	"REQUEST-932-APPLICATION-ATTACK-RCE.conf",
	"REQUEST-933-APPLICATION-ATTACK-PHP.conf",
	"REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
	"REQUEST-941-APPLICATION-ATTACK-XSS.conf",
	"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
	"REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
	"REQUEST-949-BLOCKING-EVALUATION.conf",
	"RESPONSE-950-DATA-LEAKAGES.conf",
	"RESPONSE-951-DATA-LEAKAGES-SQL.conf",
	"RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
	"RESPONSE-953-DATA-LEAKAGES-PHP.conf",
	"RESPONSE-954-DATA-LEAKAGES-IIS.conf",
	"RESPONSE-959-BLOCKING-EVALUATION.conf",
	"RESPONSE-980-CORRELATION.conf",
}

type GithubRulesService struct{}

func NewGithubRulesService() *GithubRulesService {
	return &GithubRulesService{}
}

func (s *GithubRulesService) downloadAndExtractRules(fileName string) (map[string]string, error) {
	url := baseURL + fileName
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error downloading %s: %v", fileName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error HTTP %d downloading %s", resp.StatusCode, fileName)
	}

	rules := make(map[string]string)
	reader := bufio.NewReader(resp.Body)
	var ruleBuilder strings.Builder
	var chaining bool

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %v", fileName, err)
		}

		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "SecRule") || strings.HasPrefix(line, "SecAction") || strings.HasPrefix(line, "SecMarker") || ruleBuilder.Len() != 0 || chaining {

			if strings.HasSuffix(strings.TrimRight(line, " "), "\\") {
				if ruleBuilder.Len() > 0 {
					ruleBuilder.WriteString(" ")
				}
				ruleBuilder.WriteString(strings.TrimSuffix(strings.TrimRight(line, " "), "\\"))
				continue
			}

			if ruleBuilder.Len() > 0 {
				ruleBuilder.WriteString(" ")
			}

			ruleBuilder.WriteString(line)

			if strings.Contains(line, "chain\"") {
				chaining = true
				continue
			}

			matches := msgRegex.FindStringSubmatch(ruleBuilder.String())
			if len(matches) > 1 {
				msg := matches[1]
				rules[msg] = ruleBuilder.String()
			}
			ruleBuilder.Reset()
			chaining = false

		}
	}

	return rules, nil
}

func (s *GithubRulesService) FetchAllModsecurityRules(limit int) (map[string]string, error) {
	modsecurityRules := make(map[string]string)
	processed := 0

	for _, ruleFile := range ruleFiles {
		fmt.Printf("Fetching rules for %s...\n", ruleFile)

		rules, err := s.downloadAndExtractRules(ruleFile)
		if err != nil {
			fmt.Printf("Error fetching rules for %s: %v\n", ruleFile, err)
			continue
		}

		maps.Copy(modsecurityRules, rules)

		processed += len(rules)
		if processed >= limit {
			break
		}
	}
	return modsecurityRules, nil
}
