#!/usr/bin/env python3
"""
MCP Server pour l'analyse et le troubleshooting des logs Cassandra
Permet d'analyser system.log et debug.log de tous les nodes d'un cluster

Installation:
1. pip install mcp paramiko
2. Configurer dans Claude Desktop (voir README)
"""

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, List, Dict
from collections import defaultdict
import sys
import os

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("Warning: paramiko not installed. SSH features will be disabled.", file=sys.stderr)

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
)

# Patterns de logs Cassandra communs
ERROR_PATTERNS = {
    'timeout': r'(?i)(timeout|timed out|TimedOut)',
    'oom': r'(?i)(OutOfMemory|java\.lang\.OutOfMemoryError)',
    'connection': r'(?i)(connection.*(?:refused|failed|lost|closed))',
    'compaction': r'(?i)(compaction.*(?:error|failed))',
    'repair': r'(?i)(repair.*(?:error|failed))',
    'gc': r'(?i)(GC.*(?:pause|exceeded))',
    'tombstone': r'(?i)(tombstone.*(?:warning|exceeded))',
    'dropped': r'(?i)(dropped.*messages?)',
    'unavailable': r'(?i)(UnavailableException)',
    'coordinator': r'(?i)(coordinator.*(?:timeout|failed))',
}

WARNING_PATTERNS = {
    'heap': r'(?i)(heap.*(?:pressure|warning))',
    'slow_query': r'(?i)(slow.*query)',
    'batch': r'(?i)(batch.*(?:too large|warning))',
    'streaming': r'(?i)(streaming.*(?:failed|error))',
}

# Configuration SSH par défaut
DEFAULT_SSH_CONFIG = {
    'port': 22,
    'timeout': 30,
    'default_log_paths': {
        'system': '/var/log/cassandra/system.log',
        'debug': '/var/log/cassandra/debug.log'
    }
}


class SSHLogRetriever:
    """Gestionnaire de connexions SSH pour récupérer les logs"""
    
    def __init__(self):
        self.connections = {}
        
    def connect(self, host: str, username: str, password: Optional[str] = None,
                key_filename: Optional[str] = None, port: int = 22) -> paramiko.SSHClient:
        """Établit une connexion SSH"""
        if not SSH_AVAILABLE:
            raise RuntimeError("paramiko n'est pas installé. Installez-le avec: pip install paramiko")
        
        conn_key = f"{username}@{host}:{port}"
        
        # Réutiliser la connexion si elle existe
        if conn_key in self.connections:
            try:
                transport = self.connections[conn_key].get_transport()
                if transport and transport.is_active():
                    return self.connections[conn_key]
            except:
                pass
        
        # Créer une nouvelle connexion
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if key_filename:
                # Authentification par clé
                key_filename = os.path.expanduser(key_filename)
                client.connect(
                    host,
                    port=port,
                    username=username,
                    key_filename=key_filename,
                    timeout=DEFAULT_SSH_CONFIG['timeout']
                )
            elif password:
                # Authentification par mot de passe
                client.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=DEFAULT_SSH_CONFIG['timeout']
                )
            else:
                # Essayer avec l'agent SSH ou les clés par défaut
                client.connect(
                    host,
                    port=port,
                    username=username,
                    timeout=DEFAULT_SSH_CONFIG['timeout']
                )
            
            self.connections[conn_key] = client
            return client
            
        except Exception as e:
            raise ConnectionError(f"Impossible de se connecter à {host}: {str(e)}")
    
    def read_log_file(self, client: paramiko.SSHClient, remote_path: str,
                     tail_lines: Optional[int] = None) -> str:
        """Lit un fichier de log distant"""
        try:
            if tail_lines:
                # Lire seulement les N dernières lignes
                command = f"tail -n {tail_lines} {remote_path}"
            else:
                # Lire tout le fichier
                command = f"cat {remote_path}"
            
            stdin, stdout, stderr = client.exec_command(command)
            error = stderr.read().decode('utf-8')
            
            if error and 'No such file' in error:
                raise FileNotFoundError(f"Fichier non trouvé: {remote_path}")
            elif error:
                raise RuntimeError(f"Erreur lors de la lecture: {error}")
            
            content = stdout.read().decode('utf-8', errors='replace')
            return content
            
        except Exception as e:
            raise RuntimeError(f"Erreur lors de la lecture du fichier: {str(e)}")
    
    def list_log_files(self, client: paramiko.SSHClient, log_dir: str) -> List[str]:
        """Liste les fichiers de log dans un répertoire"""
        try:
            command = f"ls -1 {log_dir}/*.log 2>/dev/null || true"
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            
            files = [f.strip() for f in output.split('\n') if f.strip()]
            return files
            
        except Exception as e:
            return []
    
    def close_all(self):
        """Ferme toutes les connexions SSH"""
        for client in self.connections.values():
            try:
                client.close()
            except:
                pass
        self.connections.clear()


class CassandraLogAnalyzer:
    """Analyseur de logs Cassandra"""
    
    def __init__(self):
        self.log_entries = []
        self.nodes = {}
        
    def parse_log_line(self, line: str, node_name: str) -> Optional[dict]:
        """Parse une ligne de log Cassandra"""
        # Format typique: LEVEL [timestamp] [thread] class:line - message
        pattern = r'(\w+)\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+([^:]+):(\d+)\s+-\s+(.*)'
        match = re.match(pattern, line)
        
        if match:
            level, timestamp, thread, class_name, line_num, message = match.groups()
            return {
                'node': node_name,
                'level': level,
                'timestamp': timestamp,
                'thread': thread,
                'class': class_name,
                'line': line_num,
                'message': message
            }
        return None
    
    def detect_issues(self, message: str) -> list:
        """Détecte les problèmes dans un message de log"""
        issues = []
        
        for issue_type, pattern in ERROR_PATTERNS.items():
            if re.search(pattern, message):
                issues.append(('ERROR', issue_type))
        
        for issue_type, pattern in WARNING_PATTERNS.items():
            if re.search(pattern, message):
                issues.append(('WARNING', issue_type))
        
        return issues
    
    def analyze_logs(self, log_data: dict) -> dict:
        """Analyse les logs de tous les nodes"""
        analysis = {
            'summary': {},
            'errors_by_node': defaultdict(list),
            'warnings_by_node': defaultdict(list),
            'issue_counts': defaultdict(int),
            'timeline': [],
            'recommendations': []
        }
        
        for node_name, log_content in log_data.items():
            lines = log_content.split('\n')
            error_count = 0
            warning_count = 0
            
            for line in lines:
                if not line.strip():
                    continue
                    
                entry = self.parse_log_line(line, node_name)
                if not entry:
                    continue
                
                issues = self.detect_issues(entry['message'])
                
                if entry['level'] == 'ERROR' or any(i[0] == 'ERROR' for i in issues):
                    error_count += 1
                    analysis['errors_by_node'][node_name].append(entry)
                    
                if entry['level'] == 'WARN' or any(i[0] == 'WARNING' for i in issues):
                    warning_count += 1
                    analysis['warnings_by_node'][node_name].append(entry)
                
                for severity, issue_type in issues:
                    analysis['issue_counts'][issue_type] += 1
                    
                if entry['level'] in ['ERROR', 'WARN']:
                    analysis['timeline'].append(entry)
            
            analysis['summary'][node_name] = {
                'errors': error_count,
                'warnings': warning_count,
                'total_lines': len(lines)
            }
        
        # Générer des recommandations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _generate_recommendations(self, analysis: dict) -> list:
        """Génère des recommandations basées sur l'analyse"""
        recommendations = []
        
        if analysis['issue_counts'].get('timeout', 0) > 10:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Timeouts fréquents',
                'recommendation': 'Vérifier la latence réseau, augmenter les timeouts, ou optimiser les requêtes'
            })
        
        if analysis['issue_counts'].get('oom', 0) > 0:
            recommendations.append({
                'severity': 'CRITICAL',
                'issue': 'Out Of Memory détecté',
                'recommendation': 'Augmenter la heap JVM ou réduire la charge. Vérifier les fuites mémoire.'
            })
        
        if analysis['issue_counts'].get('tombstone', 0) > 5:
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'Warnings tombstone',
                'recommendation': 'Revoir le modèle de données, ajuster gc_grace_seconds, ou augmenter tombstone_warn_threshold'
            })
        
        if analysis['issue_counts'].get('gc', 0) > 5:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Pauses GC excessives',
                'recommendation': 'Optimiser la heap JVM, considérer G1GC, ou réduire la charge'
            })
        
        if analysis['issue_counts'].get('dropped', 0) > 10:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Messages droppés',
                'recommendation': 'Le cluster est surchargé. Ajouter des nodes ou optimiser les requêtes.'
            })
        
        return recommendations
    
    def search_pattern(self, log_data: dict, pattern: str, 
                      case_sensitive: bool = False) -> list:
        """Recherche un pattern dans tous les logs"""
        flags = 0 if case_sensitive else re.IGNORECASE
        results = []
        
        for node_name, log_content in log_data.items():
            lines = log_content.split('\n')
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, flags):
                    results.append({
                        'node': node_name,
                        'line_number': i,
                        'content': line.strip()
                    })
        
        return results


# Instance du serveur MCP
server = Server("cassandra-log-analyzer")
analyzer = CassandraLogAnalyzer()
ssh_retriever = SSHLogRetriever()

# Stockage temporaire des logs
logs_storage = {}
# Stockage des connexions SSH configurées
ssh_connections_config = {}


@server.list_resources()
async def handle_list_resources() -> list[Resource]:
    """Liste les ressources disponibles"""
    return [
        Resource(
            uri="cassandra://logs/analysis",
            name="Analyse des logs Cassandra",
            description="Résultats de l'analyse des logs de tous les nodes",
            mimeType="application/json",
        ),
        Resource(
            uri="cassandra://logs/nodes",
            name="Liste des nodes",
            description="Liste des nodes du cluster avec leurs logs",
            mimeType="application/json",
        )
    ]


@server.read_resource()
async def handle_read_resource(uri: str) -> str:
    """Lit une ressource"""
    if uri == "cassandra://logs/analysis":
        if not logs_storage:
            return json.dumps({"error": "Aucun log chargé"})
        
        analysis = analyzer.analyze_logs(logs_storage)
        return json.dumps(analysis, indent=2, ensure_ascii=False)
    
    elif uri == "cassandra://logs/nodes":
        return json.dumps({
            "nodes": list(logs_storage.keys()),
            "total_nodes": len(logs_storage)
        }, indent=2)
    
    else:
        raise ValueError(f"Ressource inconnue: {uri}")


@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """Liste les outils disponibles"""
    tools = [
        Tool(
            name="configure_ssh_node",
            description="Configure les paramètres SSH pour un node Cassandra.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node_name": {
                        "type": "string",
                        "description": "Nom du node"
                    },
                    "host": {
                        "type": "string",
                        "description": "Adresse IP ou hostname"
                    },
                    "username": {
                        "type": "string",
                        "description": "Nom d'utilisateur SSH"
                    },
                    "password": {
                        "type": "string",
                        "description": "Mot de passe SSH (optionnel)"
                    },
                    "key_file": {
                        "type": "string",
                        "description": "Chemin vers la clé privée SSH"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port SSH",
                        "default": 22
                    },
                    "log_directory": {
                        "type": "string",
                        "description": "Répertoire des logs Cassandra",
                        "default": "/var/log/cassandra"
                    }
                },
                "required": ["node_name", "host", "username"]
            }
        ),
        Tool(
            name="load_logs_from_ssh",
            description="Charge les logs d'un node via SSH.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node_name": {
                        "type": "string",
                        "description": "Nom du node configuré"
                    },
                    "log_type": {
                        "type": "string",
                        "enum": ["system", "debug", "both"],
                        "description": "Type de log",
                        "default": "system"
                    },
                    "tail_lines": {
                        "type": "integer",
                        "description": "Nombre de lignes"
                    }
                },
                "required": ["node_name"]
            }
        ),
        Tool(
            name="load_logs_from_all_nodes",
            description="Charge les logs de tous les nodes SSH configurés.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_type": {
                        "type": "string",
                        "enum": ["system", "debug", "both"],
                        "description": "Type de log",
                        "default": "system"
                    },
                    "tail_lines": {
                        "type": "integer",
                        "description": "Nombre de lignes par fichier"
                    }
                }
            }
        ),
        Tool(
            name="load_logs",
            description="Charge les logs manuellement (copier-coller)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node_name": {
                        "type": "string",
                        "description": "Nom du node"
                    },
                    "log_content": {
                        "type": "string",
                        "description": "Contenu du fichier de log"
                    },
                    "log_type": {
                        "type": "string",
                        "enum": ["system", "debug"],
                        "description": "Type de log"
                    }
                },
                "required": ["node_name", "log_content"]
            }
        ),
        Tool(
            name="analyze_cluster",
            description="Analyse tous les logs chargés et génère un rapport complet.",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_timeline": {
                        "type": "boolean",
                        "description": "Inclure la timeline des événements",
                        "default": True
                    }
                }
            }
        ),
        Tool(
            name="search_logs",
            description="Recherche un pattern dans tous les logs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Pattern regex"
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "description": "Sensible à la casse",
                        "default": False
                    },
                    "node_filter": {
                        "type": "string",
                        "description": "Filtrer par node"
                    }
                },
                "required": ["pattern"]
            }
        ),
        Tool(
            name="get_errors",
            description="Récupère toutes les erreurs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node_name": {
                        "type": "string",
                        "description": "Nom du node"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Nombre maximum d'erreurs",
                        "default": 50
                    }
                }
            }
        ),
        Tool(
            name="compare_nodes",
            description="Compare les métriques entre nodes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Liste des nodes"
                    }
                }
            }
        ),
        Tool(
            name="detect_issues",
            description="Détecte les problèmes connus.",
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["all", "critical", "high", "medium"],
                        "description": "Niveau de sévérité",
                        "default": "all"
                    }
                }
            }
        )
    ]
    
    if not SSH_AVAILABLE:
        tools = [t for t in tools if 'ssh' not in t.name]
    
    return tools


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Gère les appels d'outils"""
    
    if name == "configure_ssh_node":
        node_name = arguments["node_name"]
        host = arguments["host"]
        username = arguments["username"]
        password = arguments.get("password")
        key_file = arguments.get("key_file")
        port = arguments.get("port", 22)
        log_directory = arguments.get("log_directory", "/var/log/cassandra")
        
        ssh_connections_config[node_name] = {
            "host": host,
            "username": username,
            "password": password,
            "key_file": key_file,
            "port": port,
            "log_directory": log_directory
        }
        
        try:
            client = ssh_retriever.connect(host, username, password, key_file, port)
            
            stdin, stdout, stderr = client.exec_command(f"test -d {log_directory} && echo 'exists'")
            output = stdout.read().decode('utf-8').strip()
            
            if output != 'exists':
                return [TextContent(
                    type="text",
                    text=f"Configuration SSH sauvegardée pour '{node_name}' ({host}). ATTENTION: Le répertoire {log_directory} n'existe pas sur le serveur."
                )]
            
            log_files = ssh_retriever.list_log_files(client, log_directory)
            
            files_list = '\n'.join(['  - ' + f for f in log_files[:5]])
            more_text = ' ...' if len(log_files) > 5 else ''
            
            return [TextContent(
                type="text",
                text=f"Configuration SSH réussie pour '{node_name}'\nHost: {host}:{port}\nUser: {username}\nAuth: {'Clé SSH' if key_file else 'Mot de passe' if password else 'Agent SSH'}\nRépertoire: {log_directory}\nFichiers trouvés: {len(log_files)}\n{files_list}{more_text}"
            )]
            
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Configuration sauvegardée mais échec de connexion à '{node_name}'\nErreur: {str(e)}\nVérifiez les credentials."
            )]
    
    elif name == "load_logs_from_ssh":
        node_name = arguments["node_name"]
        log_type = arguments.get("log_type", "system")
        tail_lines = arguments.get("tail_lines")
        
        if node_name not in ssh_connections_config:
            configured = ', '.join(ssh_connections_config.keys()) or 'aucun'
            return [TextContent(
                type="text",
                text=f"Node '{node_name}' non configuré. Utilisez configure_ssh_node d'abord. Nodes configurés: {configured}"
            )]
        
        config = ssh_connections_config[node_name]
        
        try:
            client = ssh_retriever.connect(
                config["host"],
                config["username"],
                config["password"],
                config["key_file"],
                config["port"]
            )
            
            logs_loaded = []
            
            if log_type in ["system", "both"]:
                system_log_path = f"{config['log_directory']}/system.log"
                try:
                    content = ssh_retriever.read_log_file(client, system_log_path, tail_lines)
                    logs_storage[f"{node_name}_system"] = content
                    line_count = len(content.split('\n'))
                    logs_loaded.append(f"system.log ({line_count} lignes)")
                except Exception as e:
                    logs_loaded.append(f"system.log (ERREUR: {str(e)})")
            
            if log_type in ["debug", "both"]:
                debug_log_path = f"{config['log_directory']}/debug.log"
                try:
                    content = ssh_retriever.read_log_file(client, debug_log_path, tail_lines)
                    logs_storage[f"{node_name}_debug"] = content
                    line_count = len(content.split('\n'))
                    logs_loaded.append(f"debug.log ({line_count} lignes)")
                except Exception as e:
                    logs_loaded.append(f"debug.log (ERREUR: {str(e)})")
            
            loaded_text = '\n'.join(['  - ' + log for log in logs_loaded])
            total_nodes = len(set(k.rsplit('_', 1)[0] for k in logs_storage.keys()))
            
            return [TextContent(
                type="text",
                text=f"Logs chargés depuis '{node_name}' ({config['host']})\n{loaded_text}\n\nTotal nodes avec logs: {total_nodes}"
            )]
            
        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Erreur lors du chargement des logs de '{node_name}'\nErreur: {str(e)}"
            )]
    
    elif name == "load_logs_from_all_nodes":
        log_type = arguments.get("log_type", "system")
        tail_lines = arguments.get("tail_lines")
        
        if not ssh_connections_config:
            return [TextContent(
                type="text",
                text="Aucun node SSH configuré. Utilisez configure_ssh_node."
            )]
        
        results = []
        success_count = 0
        
        for node_name in ssh_connections_config.keys():
            try:
                result = await handle_call_tool("load_logs_from_ssh", {
                    "node_name": node_name,
                    "log_type": log_type,
                    "tail_lines": tail_lines
                })
                results.append(f"OK {node_name}")
                success_count += 1
            except Exception as e:
                results.append(f"ERREUR {node_name}: {str(e)}")
        
        results_text = '\n'.join(results)
        total = len(ssh_connections_config)
        
        return [TextContent(
            type="text",
            text=f"Chargement de tous les nodes\n\nSuccès: {success_count}/{total}\n\n{results_text}"
        )]
    
    elif name == "load_logs":
        node_name = arguments["node_name"]
        log_content = arguments["log_content"]
        log_type = arguments.get("log_type", "system")
        
        logs_storage[node_name] = log_content
        line_count = len(log_content.split('\n'))
        total_nodes = len(logs_storage)
        
        return [TextContent(
            type="text",
            text=f"Logs {log_type} chargés pour '{node_name}'\nNombre de lignes: {line_count}\nTotal nodes: {total_nodes}"
        )]
    
    elif name == "analyze_cluster":
        if not logs_storage:
            return [TextContent(
                type="text",
                text="Aucun log chargé. Utilisez load_logs d'abord."
            )]
        
        analysis = analyzer.analyze_logs(logs_storage)
        
        report = "# Analyse du Cluster Cassandra\n\n"
        
        report += "## Résumé par Node\n"
        for node, stats in analysis['summary'].items():
            report += f"\n### {node}\n"
            report += f"- Erreurs: {stats['errors']}\n"
            report += f"- Warnings: {stats['warnings']}\n"
            report += f"- Total lignes: {stats['total_lines']}\n"
        
        report += "\n## Problèmes Détectés\n"
        for issue, count in sorted(analysis['issue_counts'].items(), 
                                   key=lambda x: x[1], reverse=True):
            report += f"- {issue}: {count} occurrences\n"
        
        if analysis['recommendations']:
            report += "\n## Recommandations\n"
            for rec in analysis['recommendations']:
                emoji = "CRITIQUE" if rec['severity'] == 'CRITICAL' else "IMPORTANT" if rec['severity'] == 'HIGH' else "ATTENTION"
                report += f"\n{emoji} **{rec['issue']}** ({rec['severity']})\n"
                report += f"→ {rec['recommendation']}\n"
        
        return [TextContent(
            type="text",
            text=report
        )]
    
    elif name == "search_logs":
        pattern = arguments["pattern"]
        case_sensitive = arguments.get("case_sensitive", False)
        node_filter = arguments.get("node_filter")
        
        search_data = logs_storage
        if node_filter:
            search_data = {node_filter: logs_storage.get(node_filter, "")}
        
        results = analyzer.search_pattern(search_data, pattern, case_sensitive)
        
        if not results:
            return [TextContent(
                type="text",
                text=f"Aucun résultat pour: {pattern}"
            )]
        
        report = f"# Résultats de recherche: '{pattern}'\n\nTotal: {len(results)}\n\n"
        
        for result in results[:100]:
            report += f"**{result['node']}** (ligne {result['line_number']})\n"
            report += f"```\n{result['content']}\n```\n\n"
        
        if len(results) > 100:
            report += f"\n... et {len(results) - 100} résultats supplémentaires"
        
        return [TextContent(type="text", text=report)]
    
    elif name == "get_errors":
        if not logs_storage:
            return [TextContent(
                type="text",
                text="Aucun log chargé."
            )]
        
        analysis = analyzer.analyze_logs(logs_storage)
        node_name = arguments.get("node_name")
        limit = arguments.get("limit", 50)
        
        errors = []
        if node_name:
            errors = analysis['errors_by_node'].get(node_name, [])
        else:
            for node_errors in analysis['errors_by_node'].values():
                errors.extend(node_errors)
        
        errors = errors[:limit]
        
        report = f"# Erreurs ({len(errors)})\n\n"
        for err in errors:
            report += f"**{err['node']}** [{err['timestamp']}]\n"
            report += f"```\n{err['message']}\n```\n\n"
        
        return [TextContent(type="text", text=report)]
    
    elif name == "compare_nodes":
        nodes = arguments.get("nodes", list(logs_storage.keys()))
        
        analysis = analyzer.analyze_logs(logs_storage)
        
        report = "# Comparaison des Nodes\n\n"
        report += "| Node | Erreurs | Warnings | Lignes |\n"
        report += "|------|---------|----------|--------|\n"
        
        for node in nodes:
            if node in analysis['summary']:
                stats = analysis['summary'][node]
                report += f"| {node} | {stats['errors']} | {stats['warnings']} | {stats['total_lines']} |\n"
        
        return [TextContent(type="text", text=report)]
    
    elif name == "detect_issues":
        severity = arguments.get("severity", "all")
        
        analysis = analyzer.analyze_logs(logs_storage)
        
        report = "# Problèmes Détectés\n\n"
        
        for rec in analysis['recommendations']:
            if severity == "all" or rec['severity'].lower() == severity:
                emoji = "CRITIQUE" if rec['severity'] == 'CRITICAL' else "IMPORTANT" if rec['severity'] == 'HIGH' else "ATTENTION"
                report += f"{emoji} **{rec['issue']}** ({rec['severity']})\n"
                report += f"→ {rec['recommendation']}\n\n"
        
        return [TextContent(type="text", text=report)]
    
    else:
        raise ValueError(f"Outil inconnu: {name}")


async def main():
    """Point d'entrée principal"""
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="cassandra-log-analyzer",
                    server_version="2.0.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        ssh_retriever.close_all()


if __name__ == "__main__":
    asyncio.run(main())