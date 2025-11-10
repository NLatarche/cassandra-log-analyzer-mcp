# 🔍 Cassandra Log Analyzer MCP

A Model Context Protocol (MCP) server for analyzing and troubleshooting Apache Cassandra cluster logs using Claude AI.


## 🌟 Features

- **🔐 SSH Integration**: Connect directly to remote Cassandra nodes
- **📊 Automated Analysis**: Intelligent pattern detection for common Cassandra issues
- **🔍 Log Parsing**: Parse system.log and debug.log files
- **🚨 Issue Detection**: Automatically detect timeouts, OOM, GC pauses, tombstones, etc.
- **💡 Smart Recommendations**: Get actionable recommendations based on detected issues
- **📈 Node Comparison**: Compare metrics across multiple nodes
- **🔎 Pattern Search**: Search logs using regex patterns
- **🌐 Multi-Node Support**: Analyze entire clusters simultaneously

## 📋 Prerequisites

- Python 3.10 or higher
- Claude Desktop
- SSH access to Cassandra nodes
- Apache Cassandra cluster

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/cassandra-mcp.git
cd cassandra-mcp
```

### 2. Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Claude Desktop

Edit your Claude Desktop config file:

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`  
**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Linux**: `~/.config/Claude/claude_desktop_config.json`

Add the MCP server configuration:

```json
{
  "mcpServers": {
    "cassandra-logs": {
      "command": "/path/to/venv/bin/python",
      "args": [
        "/path/to/cassandra_log_analyzer.py"
      ]
    }
  }
}
```

### 5. Restart Claude Desktop

Quit and restart Claude Desktop to load the MCP server.

## 💻 Usage

### Configure SSH Access to Nodes

```
Configure my 3 Cassandra nodes:
- node1: xx.xxx.xxx.xxx, user: admin, key: ~/.ssh/id_rsa
- node2: xxx.xxx.xxx.xxx, user: admin, key: ~/.ssh/id_rsa
- node3: xxx.xxx.xxx.xxx, user: admin, key: ~/.ssh/id_rsa
```

### Load Logs from All Nodes

```
Load the last 5000 lines of system.log from all nodes
```

### Analyze the Cluster

```
Analyze the cluster and give me a detailed report with recommendations
```

### Search for Specific Issues

```
Search for all timeout errors in the logs
```

```
Are there any critical errors in the last 24 hours?
```

### Compare Nodes

```
Compare the performance metrics between the 3 nodes
```

## 🛠️ Available Tools

The MCP server provides 9 tools:

1. **configure_ssh_node** - Configure SSH connection to a Cassandra node
2. **load_logs_from_ssh** - Load logs from a node via SSH
3. **load_logs_from_all_nodes** - Load logs from all configured nodes
4. **load_logs** - Manually load logs (copy-paste)
5. **analyze_cluster** - Perform complete cluster analysis
6. **search_logs** - Search logs using regex patterns
7. **get_errors** - Extract all errors from logs
8. **compare_nodes** - Compare metrics between nodes
9. **detect_issues** - Detect known Cassandra issues

## 🔍 Detected Issues

The analyzer automatically detects:

### Errors
- ⏱️ Timeouts (read/write/coordinator)
- 💾 Out of Memory (OOM)
- 🔌 Connection issues
- 🗜️ Compaction failures
- 🔧 Repair failures
- 🗑️ GC pauses
- ⚰️ Tombstone warnings
- 📉 Dropped messages
- ❌ Unavailable exceptions

### Warnings
- 📊 Heap pressure
- 🐌 Slow queries
- 📦 Large batches
- 📡 Streaming issues

## 📊 Example Analysis Output

```markdown
# Cassandra Cluster Analysis

## Summary by Node

### cassandra-node-1
- Errors: 23
- Warnings: 45
- Total lines: 5000

### cassandra-node-2
- Errors: 18
- Warnings: 38
- Total lines: 5000

### cassandra-node-3
- Errors: 31
- Warnings: 52
- Total lines: 5000

## Detected Issues
- timeout: 15 occurrences
- gc: 8 occurrences
- tombstone: 6 occurrences

## Recommendations

🔴 **Timeouts fréquents** (HIGH)
→ Check network latency, increase timeouts, or optimize queries

🟠 **GC Pauses excessives** (HIGH)
→ Optimize JVM heap, consider G1GC, or reduce load
```

## 🏗️ Architecture

```
┌─────────────────────────────────┐
│  User                           │
│  "Analyze my Cassandra logs"    │
└────────────┬────────────────────┘
             │
             ↓ Natural language
┌─────────────────────────────────┐
│  Claude Desktop                 │
│  - Understands request          │
│  - Calls appropriate tools      │
└────────────┬────────────────────┘
             │
             ↓ MCP Protocol
┌─────────────────────────────────┐
│  MCP Server (Python)            │
│  - SSH connection management    │
│  - Log parsing & analysis       │
│  - Issue detection              │
└────────────┬────────────────────┘
             │
             ↓ SSH
┌─────────────────────────────────┐
│  Cassandra Nodes (Remote)       │
│  - system.log                   │
│  - debug.log                    │
└─────────────────────────────────┘
```

## 🔒 Security Considerations

- SSH keys are stored locally and never transmitted
- Support for SSH key authentication (recommended)
- Password authentication also supported
- All connections use standard SSH security
- No data is sent to external services

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


## 🙏 Acknowledgments

- Built with [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- Powered by [Claude](https://claude.ai/) by Anthropic
- SSH functionality via [Paramiko](https://www.paramiko.org/)

## 📧 Contact


Project Link: [https://github.com/yourusername/cassandra-mcp](https://github.com/NLatarche/cassandra-mcp)

## 🗺️ Roadmap

- [ ] Real-time log streaming
- [ ] Integration with nodetool metrics
- [ ] Performance metrics analysis
- [ ] Automated alerting
- [ ] Report generation (PDF/HTML)
- [ ] Support for other log formats
- [ ] Web dashboard for visualization

---

**Note**: This tool is designed for log analysis and troubleshooting. Always follow your organization's security policies when accessing production systems.
