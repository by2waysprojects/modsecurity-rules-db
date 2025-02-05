# ModSecurity Rules Database with Neo4j

`modsecurity-rules-db` is a Go service designed to fetch, parse, and store ModSecurity rules in a Neo4j database. The service retrieves rule files from GitHub, extracts meaningful data such as the rule message, and organizes them as nodes within Neo4j for advanced querying and security analysis.

## 🚀 Features

- 🔍 Fetches and stores **ModSecurity rules** from a remote GitHub repository.
- 🛢️ Saves the rules in a **Neo4j database** as structured nodes.
- 📦 Provides a REST API to retrieve and query rules efficiently.
- 🔗 Supports relationships between rules and potential attack categories.

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/by2waysprojects/modsecurity-rules-db.git
   cd modsecurity-rules-db
   ```

2. **Set up Neo4j**:
   - Install Neo4j: [Neo4j Installation Guide](https://neo4j.com/docs/operations-manual/current/installation/)
   - Start the Neo4j database:
     ```bash
     neo4j start
     ```
   - Configure the database credentials in your environment:
     ```bash
     export NEO4J_URI="bolt://localhost:7687"
     export NEO4J_USER="neo4j"
     export NEO4J_PASSWORD="your_password"
     ```

3. **Build the service**:
   ```bash
   go build -o modsecurity-rules-db ./cmd
   ```

4. **Run the service**:
   ```bash
   ./modsecurity-rules-db
   ```

## 🔧 Usage

The service exposes a REST API to fetch and store ModSecurity rules into the database.

### Endpoint: `/save-modsecurity-rules`

#### Method: `GET`

#### Description:
Fetches ModSecurity rules from GitHub and stores them in Neo4j.

#### Example Request:
```bash
curl -X POST http://localhost:8080/save-modsecurity-rules
```

### Data Storage in Neo4j

- **Nodes**:
  - `Rule` nodes:
    - **Fields**:
      - `id`: The rule message (describes what the rule detects).
      - `rule`: The full ModSecurity rule as a string
      - `action`: Action to take if rule triggered.

## 📚 Example Cypher Queries

### List All Rules
```cypher
MATCH (r:ModSecRule)
RETURN r.id, r.rule
```

### Search Rules by Message Keyword
```cypher
MATCH (r:ModSecRule)
WHERE r.id CONTAINS "SQL Injection"
RETURN r
```

## 🌍 How It Works

1. **Fetch Data**:
   - Downloads ModSecurity rule files from GitHub.
2. **Parse Rules**:
   - Extracts key fields (`msg`, full rule content).
3. **Store in Neo4j**:
   - Creates `Rule` nodes with relevant fields.

## 📚 Future Features

- 🌐 Additional API endpoints for querying rules dynamically.
- 📊 Rule categorization and visualization for attack trends.
- 🛡️ Integration with real-time security monitoring tools.

## 🤝 Contributions

Contributions are welcome! Please fork the repository, create a feature branch, and submit a pull request.

## 🛡️ License

This project is licensed under the Apache License. See the [LICENSE](LICENSE) file for details.

## 🌟 Acknowledgments

Special thanks to the ModSecurity community for providing open-source security rules and to the Neo4j team for their graph database technology.