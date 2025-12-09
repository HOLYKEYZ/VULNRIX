"""
Node Load Balancer
Distributes scanning tasks across multiple nodes.
"""

import requests
import concurrent.futures
from typing import List, Dict, Any

class NodeBalancer:
    """
    Manages a pool of scanner nodes and distributes work.
    """
    
    def __init__(self, nodes: List[str]):
        self.nodes = nodes
        self.current_node = 0

    def _get_next_node(self) -> str:
        """Round-robin node selection"""
        if not self.nodes:
            raise ValueError("No nodes available")
        node = self.nodes[self.current_node]
        self.current_node = (self.current_node + 1) % len(self.nodes)
        return node

    def scan_distributed(self, files: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Scan multiple files in parallel across nodes.
        files: List of {"path": "...", "code": "..."}
        """
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.nodes) * 2) as executor:
            future_to_file = {}
            
            for file_data in files:
                node = self._get_next_node()
                future = executor.submit(self._scan_single, node, file_data)
                future_to_file[future] = file_data['path']
                
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append({
                        "file": file_path,
                        "result": result
                    })
                except Exception as e:
                    results.append({
                        "file": file_path,
                        "result": {"status": "ERROR", "error": str(e)}
                    })
                    
        return results

    def _scan_single(self, node_url: str, file_data: Dict[str, str]) -> Dict[str, Any]:
        """Send a single file to a node"""
        try:
            resp = requests.post(
                f"{node_url}/scan",
                json={
                    "code": file_data['code'],
                    "filename": file_data['path']
                },
                timeout=120
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            return {"status": "ERROR", "error": f"Node {node_url} failed: {e}"}
