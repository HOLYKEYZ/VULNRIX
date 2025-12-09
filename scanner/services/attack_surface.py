"""
Attack Surface Mapping Service for VULNRIX.
Creates a graph visualization connecting OSINT findings to code vulnerabilities.
"""

from typing import Dict, List, Any, Optional
import hashlib


class AttackSurfaceMapper:
    """
    Creates a unified attack surface map connecting:
    - Identity information (emails, usernames, names)
    - Technical assets (domains, IPs, services)
    - Vulnerabilities (code issues, breaches)
    - Relationships between entities
    """
    
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.node_ids = set()
    
    def _add_node(self, node_id: str, node_type: str, label: str, 
                  severity: str = None, metadata: Dict = None) -> str:
        """Add a node to the graph."""
        if node_id in self.node_ids:
            return node_id
        
        node = {
            'id': node_id,
            'type': node_type,
            'label': label,
            'group': node_type,
        }
        
        if severity:
            node['severity'] = severity
            node['color'] = self._severity_color(severity)
        
        if metadata:
            node['metadata'] = metadata
        
        self.nodes.append(node)
        self.node_ids.add(node_id)
        return node_id
    
    def _add_edge(self, source: str, target: str, relationship: str = 'connected'):
        """Add an edge between nodes."""
        edge = {
            'from': source,
            'to': target,
            'label': relationship,
            'arrows': 'to'
        }
        self.edges.append(edge)
    
    def _severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            'critical': '#dc2626',
            'high': '#ef4444',
            'medium': '#f59e0b',
            'low': '#10b981',
            'info': '#3b82f6'
        }
        return colors.get(severity.lower(), '#6b7280')
    
    def _generate_id(self, prefix: str, value: str) -> str:
        """Generate a unique ID for a node."""
        hash_val = hashlib.md5(value.encode()).hexdigest()[:8]
        return f"{prefix}_{hash_val}"
    
    def add_identity(self, identity_type: str, value: str) -> str:
        """Add an identity node (email, username, name)."""
        node_id = self._generate_id(identity_type, value)
        
        icons = {
            'email': '📧',
            'username': '👤',
            'name': '🏷️',
            'phone': '📱'
        }
        
        label = f"{icons.get(identity_type, '🔑')} {value}"
        self._add_node(node_id, 'identity', label, metadata={'value': value})
        return node_id
    
    def add_asset(self, asset_type: str, value: str, metadata: Dict = None) -> str:
        """Add a technical asset node (domain, IP, service)."""
        node_id = self._generate_id(asset_type, value)
        
        icons = {
            'domain': '🌐',
            'ip': '📍',
            'service': '⚙️',
            'port': '🔌'
        }
        
        label = f"{icons.get(asset_type, '💻')} {value}"
        self._add_node(node_id, 'asset', label, metadata=metadata)
        return node_id
    
    def add_breach(self, name: str, domain: str = None, 
                   breach_date: str = None, data_classes: List[str] = None) -> str:
        """Add a data breach node."""
        node_id = self._generate_id('breach', name)
        
        label = f"⚠️ {name}"
        metadata = {
            'domain': domain,
            'breach_date': breach_date,
            'data_classes': data_classes or []
        }
        
        self._add_node(node_id, 'breach', label, severity='high', metadata=metadata)
        return node_id
    
    def add_vulnerability(self, vuln_type: str, file: str, line: int,
                          severity: str, cwe: str = None) -> str:
        """Add a code vulnerability node."""
        node_id = self._generate_id('vuln', f"{file}:{line}")
        
        label = f"🔴 {vuln_type} @ {file}:{line}"
        metadata = {
            'file': file,
            'line': line,
            'cwe': cwe
        }
        
        self._add_node(node_id, 'vulnerability', label, severity=severity, metadata=metadata)
        return node_id
    
    def add_social_account(self, platform: str, username: str, url: str = None) -> str:
        """Add a social media account node."""
        node_id = self._generate_id('social', f"{platform}_{username}")
        
        icons = {
            'twitter': '🐦',
            'linkedin': '💼',
            'github': '💻',
            'instagram': '📷',
            'facebook': '👥',
            'reddit': '🔴',
            'tiktok': '🎵'
        }
        
        label = f"{icons.get(platform.lower(), '📱')} @{username}"
        self._add_node(node_id, 'social', label, metadata={'platform': platform, 'url': url})
        return node_id
    
    def connect(self, source_id: str, target_id: str, relationship: str = 'connected'):
        """Connect two nodes."""
        self._add_edge(source_id, target_id, relationship)
    
    def build_from_results(self, osint_results: Dict, code_results: Dict = None) -> Dict:
        """
        Build attack surface graph from scan results.
        
        Args:
            osint_results: Results from OSINT scan
            code_results: Results from code vulnerability scan
            
        Returns:
            Graph data for vis.js visualization
        """
        # Reset graph
        self.nodes = []
        self.edges = []
        self.node_ids = set()
        
        # Add identity nodes
        email_node = None
        if osint_results.get('email'):
            email_node = self.add_identity('email', osint_results['email'])
        
        name_node = None
        if osint_results.get('name'):
            name_node = self.add_identity('name', osint_results['name'])
            if email_node:
                self.connect(name_node, email_node, 'owns')
        
        username_node = None
        if osint_results.get('username'):
            username_node = self.add_identity('username', osint_results['username'])
            if email_node:
                self.connect(email_node, username_node, 'uses')
        
        # Add domain asset
        domain_node = None
        if osint_results.get('domain'):
            domain_node = self.add_asset('domain', osint_results['domain'])
            if email_node and osint_results['email'].endswith(osint_results['domain']):
                self.connect(email_node, domain_node, 'belongs_to')
        
        # Add breaches
        breach_data = osint_results.get('breach_data', {})
        for breach in breach_data.get('breaches', []):
            breach_node = self.add_breach(
                name=breach.get('Name', 'Unknown'),
                domain=breach.get('Domain'),
                breach_date=breach.get('BreachDate'),
                data_classes=breach.get('DataClasses', [])
            )
            if email_node:
                self.connect(email_node, breach_node, 'exposed_in')
        
        # Add social accounts
        social_results = osint_results.get('social_results', {})
        for platform, accounts in social_results.items():
            if accounts:
                for account in accounts[:5]:  # Limit to 5 per platform
                    social_node = self.add_social_account(
                        platform=platform,
                        username=account.get('username', osint_results.get('username', '')),
                        url=account.get('link')
                    )
                    if username_node:
                        self.connect(username_node, social_node, 'has_account')
        
        # Add code vulnerabilities
        if code_results:
            for finding in code_results.get('findings', []):
                vuln_node = self.add_vulnerability(
                    vuln_type=finding.get('type', 'Unknown'),
                    file=finding.get('file', 'unknown'),
                    line=finding.get('line', 0),
                    severity=finding.get('severity', 'medium'),
                    cwe=finding.get('cwe')
                )
                if domain_node:
                    self.connect(domain_node, vuln_node, 'contains')
        
        return self.get_graph_data()
    
    def get_graph_data(self) -> Dict:
        """Get graph data for vis.js visualization."""
        return {
            'nodes': self.nodes,
            'edges': self.edges,
            'stats': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'identities': sum(1 for n in self.nodes if n['type'] == 'identity'),
                'assets': sum(1 for n in self.nodes if n['type'] == 'asset'),
                'breaches': sum(1 for n in self.nodes if n['type'] == 'breach'),
                'vulnerabilities': sum(1 for n in self.nodes if n['type'] == 'vulnerability'),
                'social_accounts': sum(1 for n in self.nodes if n['type'] == 'social'),
            }
        }
    
    def to_json(self) -> str:
        """Export graph to JSON."""
        import json
        return json.dumps(self.get_graph_data(), indent=2)


# Convenience function
def build_attack_surface(osint_results: Dict, code_results: Dict = None) -> Dict:
    """Build attack surface map from scan results."""
    mapper = AttackSurfaceMapper()
    return mapper.build_from_results(osint_results, code_results)
