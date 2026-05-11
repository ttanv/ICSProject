# Neo4j Docker Environment

This project provides a lightweight Neo4j environment using Docker Compose, along with an import script to rebuild the database from a Cypher export file.

---

## 1. Requirements

- Docker Desktop (Mac/Linux/Windows)
- Docker Compose [Link](https://docs.docker.com/desktop/)
- Bash shell (macOS and Linux compatible)

use the requirment.txt file to install (pandas and pyvelociraptor)

```bash
pip3 install -r requirments.txt  
```

---

# Files

```bash
+---Artifacts
|   +---Linux
|   |       Listeners.List.yaml
|   |       Process.List.yaml
|   |       Sysmon.Collector.yaml
|   |       Sysmon.Install.yaml
|   |
|   \---Windows
|           Listeners.List.yaml
|           Process.List.yaml
|           Sysmon.Collector.yaml
|           Sysmon.Install.yaml
|
\---Sysmon
        sysmon-linux.xml
        sysmon-win.xml
```

### Sysmon Folder
The **Sysmon** folder contains the rules and configuration used by the team for both Linux and Windows machines.

### Artifacts Folder
The **Artifacts** folder contains the Velociraptor artifacts used to collect logs from the machines:

- **Listeners** – Collect network-related data  
- **Process** – Collect logs related to running processes  
- **Sysmon.Collector** – Collect Sysmon data  
- **Sysmon.Install** – An artifact used to install Sysmon on both Linux and Windows systems

---
## 1. Collect logs 

Inorder to use this project you need logs to be collected from velociraptor machine, to do this you can use the collect_logs.py script and provide the flow_id 

```bash
python collect_logs.py <hunt_id> [--config CONFIG_PATH] [--output OUTPUT_DIR] [--verbose]

Example:
    python collect_logs.py F.D4VBGUC6CVB76.H
    python collect_logs.py F.D4VBGUC6CVB76.H --config ./api.config.yaml --output ./logs

```

## 2. Build Graph

After collecting the logs you need to generate the cypher file (Neo4j Graph) to do this you can use the build_graph.py script
Note: The assets.yaml file must be present for the script to correctly process the logs and generate the graph. The assets.yaml file describes the network structure and provides the information the script needs to interpret the data.

```bash
Usage:
    python build_graph.py [--logs LOGS_DIR] [--assets ASSETS_FILE] [--output OUTPUT_FILE]
    python build_graph.py --logs ./logs --assets ./assets.yaml --output ./neo4j_export.cypher

Example:
    python build_graph.py
    python build_graph.py --logs ./logs --no-cache --verbose

```
## 3. Start Neo4j with Docker Compose

Run:

```bash
docker compose up -d
```

## 4. Import Graph

Run:

```bash
bash import_data.sh neo4j_export.cypher
```

If you are using a Windows machine, you can copy the cipher file to Docker using the commands below 

```bash
docker cp neo4j_export.cypher neo4j:/root  

```
Then, access the Docker container and execute the commands below.

```bash
docker exec -it neo4j /bin/bash
cypher-shell -u USER -p PASSWORD < /root/neo4j_export.cypher
```

## 5. Setup Neo4j MCP

```bash
# Install uvx
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install mcp-neo4j-cypher
uvx mcp-neo4j-cypher
```

## 6. Configure Neo4j MCP

Example: `.vscode/mcp.json`

```json
{
	"servers": {
		"mcp-neo4j-cypher": {
			"type": "stdio",
			"command": "uvx",
            "args": [
                "--with",
                "fastmcp<2.11.4",
                "mcp-neo4j-cypher@0.5.1",
            ],
            "env": {
                "NEO4J_URI": "bolt://localhost:7687",
                "NEO4J_USER": "neo4j",
                "NEO4J_PASSWORD": "CPS@QCRI2255"
            }
		}
	},
	"inputs": []
}
```


