import json
import os
import sys

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None

class SecurityNormalizer:
    def __init__(self, results_dir='security-results'):
        self.results_dir = results_dir
        self.findings = {
            "1_secrets": [],
            "2_dependencies": [],
            "3_sast": [],
            "4_containers": [],
            "5_dast": []
        }
    
    def load_json(self, filename):
        # Esta es la línea 18 donde fallaba la indentación
        ruta_archivo = os.path.join(self.results_dir, filename)
        if not os.path.exists(ruta_archivo):
            print(f"ℹ️ Archivo no encontrado: {filename}")
            return None
        
        try:
            with open(ruta_archivo, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content: return None
                
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    hallazgos = []
                    f.seek(0)
                    for linea in f:
                        linea = linea.strip()
                        if linea.startswith('{'):
                            try:
                                hallazgos.append(json.loads(linea))
                            except: continue
                    return hallazgos if hallazgos else None
        except Exception as e:
            print(f"⚠️ Error cargando {filename}: {str(e)}")
            return None

    def process_trufflehog(self, filename='trufflehog-results.json'):
        data = self.load_json(filename)
        if not data: return
        events = data if isinstance(data, list) else [data]
        for event in events:
            if not isinstance(event, dict) or 'DetectorName' not in event: continue
            source_inc = event.get('SourceMetadata', {}).get('Data', {}).get('Git', {})
            self.findings["1_secrets"].append({
                "tool": "TruffleHog",
                "type": f"Credential Leak ({event.get('DetectorName')})",
                "file": source_inc.get('file', 'N/A'),
                "line": source_inc.get('line', 'N/A'),
                "severity": "CRITICAL"
            })

    def process_snyk(self, filename='snyk-results.json'):
        data = self.load_json(filename)
        if not data: return
        reports = data if isinstance(data, list) else [data]
        for report in reports:
            for v in report.get('vulnerabilities', []):
                if v.get('severity') in ['critical', 'high']:
                    self.findings["2_dependencies"].append({
                        "tool": "Snyk",
                        "package": v.get('packageName'),
                        "vulnerability": v.get('title'),
                        "severity": v.get('severity').upper()
                    })

    def process_semgrep(self, filename='semgrep-results.json'):
        data = self.load_json(filename)
        if not data: return
        results = data.get('results', []) if 'results' in data else []
        for result in results:
            sev = result.get('extra', {}).get('severity', '').upper()
            if sev in ['ERROR', 'HIGH', 'CRITICAL']:
                self.findings["3_sast"].append({
                    "tool": "Semgrep",
                    "rule": result.get('check_id'),
                    "file": result.get('path'),
                    "severity": sev
                })

    def process_trivy(self, filename='trivy-results.json'):
        data = self.load_json(filename)
        if not data: return
        results = data.get('Results', [])
        for res in results:
            for v in res.get('Vulnerabilities', []):
                if v.get('Severity') in ['CRITICAL', 'HIGH']:
                    self.findings["4_containers"].append({
                        "tool": "Trivy",
                        "library": v.get('PkgName'),
                        "vulnerability": v.get('VulnerabilityID'),
                        "severity": v.get('Severity')
                    })

    def process_zap(self, filename='zap-results.json'):
        data = self.load_json(filename)
        if not data: return
        for site in data.get('site', []):
            for alert in site.get('alerts', []):
                if alert.get('riskcode') in ['3', '2']:
                    self.findings["5_dast"].append({
                        "tool": "ZAP",
                        "alert": alert.get('alert'),
                        "risk": alert.get('riskdesc')
                    })

    def get_priority_phase(self):
        order = ["1_secrets", "2_dependencies", "3_sast", "4_containers", "5_dast"]
        for phase in order:
            if self.findings[phase]:
                return phase, self.findings[phase]
        return None, []

    def call_claude_ai(self, phase, issues):
        if Anthropic is None:
            return "❌ Error: dependencia 'anthropic' no instalada."

        api_key = os.environ.get("CLAUDE_API_KEY")
        if not api_key:
            return "❌ Error: API Key no configurada."

        client = Anthropic(api_key=api_key)
        prompt = f"Analiza estos fallos críticos de seguridad en la fase {phase}: {json.dumps(issues)}"
        requested_model = os.environ.get("CLAUDE_MODEL", "claude-3-5-sonnet-latest")
        candidate_models = [
            requested_model,
            "claude-3-5-sonnet-latest",
            "claude-3-5-sonnet-20240620",
        ]

        # Eliminar duplicados preservando el orden
        seen = set()
        models = []
        for model in candidate_models:
            if model and model not in seen:
                models.append(model)
                seen.add(model)

        errors = []
        for model in models:
            try:
                response = client.messages.create(
                    model=model,
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            except Exception as e:
                errors.append(f"{model}: {str(e)}")

        return "❌ Error en IA: " + " | ".join(errors)

def main():
    results_path = sys.argv[1] if len(sys.argv) > 1 else 'security-results'
    normalizer = SecurityNormalizer(results_path)
    normalizer.process_trufflehog()
    normalizer.process_snyk()
    normalizer.process_semgrep()
    normalizer.process_trivy()
    normalizer.process_zap()
    
    phase, issues = normalizer.get_priority_phase()
    summary_path = os.getenv('GITHUB_STEP_SUMMARY')
    
    if not phase:
        msg = "✅ **PROYECTO APROBADO**"
        if summary_path:
            with open(summary_path, 'a') as f: f.write(msg)
        sys.exit(0)

    report = normalizer.call_claude_ai(phase, issues)
    had_runtime_error = isinstance(report, str) and report.startswith("❌ Error")
    if summary_path:
        with open(summary_path, 'a', encoding='utf-8') as f:
            f.write(f"\n# 🤖 Reporte de Auditoría IA\n{report}")

    # Exit codes:
    # 0 -> no findings
    # 1 -> findings detected (security gate decision)
    # 2 -> runtime error (missing API key, provider error, etc.)
    if had_runtime_error:
        sys.exit(2)

    sys.exit(1)

if __name__ == "__main__":
    main()