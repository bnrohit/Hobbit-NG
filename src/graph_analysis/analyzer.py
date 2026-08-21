import networkx as nx

class AttackGraphAnalyzer:
    def __init__(self, config, logger): self.config,self.logger=config,logger
    def build_graph(self, results):
        g=nx.DiGraph()
        for host,data in (results.get("hosts",{}) or {}).items():
            g.add_node(host,kind="host")
            for port in data.get("open_ports",{}): g.add_node(f"{host}:{port}",kind="service"); g.add_edge(host,f"{host}:{port}")
        return g
    def find_attack_paths(self,g,target):
        return [] if target not in g else [{"target":target,"note":"Path inference requires an explicitly modeled trusted starting node."}]
