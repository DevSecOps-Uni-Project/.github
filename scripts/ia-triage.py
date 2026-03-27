import json
import os
import sys

class SecurityNormalizer:
    def __init__(self):
        self.findings = {
            "1_secrets": [],      # Prioridad Máxima (TruffleHog)
            "2_dependencies": [], # SCA (Snyk/Trivy)
            "3_sast": [],         # Estático (Semgrep/CodeQL)
            "4_dast": []          # Dinámico (ZAP)
        }

    def load_json(self, path):
        if not os.path.exists(path): return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except: return None

    def process_trufflehog(self, path='trufflehog-results.json'):
        """
        Normaliza hallazgos de TruffleHog.
        Busca secretos reales y metadatos del detector.
        """
        data = self.load_json(path)
        if not data: return

        # TruffleHog suele entregar un JSON por línea o una lista
        events = data if isinstance(data, list) else [data]
        
        for event in events:
            # Extraemos la información vital para el desarrollador
            detector = event.get('DetectorName', 'Unknown Detector')
            raw = event.get('Raw', '***')
            file = event.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('file', 'Unknown')
            line = event.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('line', 'N/A')
            commit = event.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('commit', 'N/A')

            self.findings["1_secrets"].append({
                "tool": "TruffleHog",
                "type": f"Secret Detector: {detector}",
                "file": file,
                "line": line,
                "commit_hash": commit,
                "severity": "CRITICAL",
                "description": f"Se ha detectado una posible credencial expuesta de tipo '{detector}'.",
                "remediation_step": "1. Rota la credencial inmediatamente. 2. Invalida el token anterior. 3. Usa GitHub Secrets para inyectar la clave en el runtime."
            })

    def process_snyk(self, path='snyk-results.json'):
        data = self.load_json(path)
        if not data: return
        reports = data if isinstance(data, list) else [data]
        for report in reports:
            for v in report.get('vulnerabilities', []):
                if v.get('severity') in ['critical', 'high']:
                    self.findings["2_dependencies"].append({
                        "tool": "Snyk",
                        "title": v.get('title'),
                        "package": v.get('packageName'),
                        "severity": v.get('severity').upper(),
                        "fix_version": v.get('fixedIn', 'Update to latest'),
                        "location": f"Dependency: {v.get('packageName')}@{v.get('version')}"
                    })

    def process_semgrep(self, path='semgrep-results.sarif'):
        data = self.load_json(path)
        if not data: return
        for run in data.get('runs', []):
            for result in run.get('results', []):
                if result.get('level') == 'error':
                    loc = result.get('locations', [{}])[0].get('physicalLocation', {})
                    self.findings["3_sast"].append({
                        "tool": "Semgrep",
                        "rule": result.get('ruleId'),
                        "file": loc.get('artifactLocation', {}).get('uri'),
                        "line": loc.get('region', {}).get('startLine'),
                        "message": result.get('message', {}).get('text')
                    })

    def get_priority_finding(self):
        # Orden de prioridad estricto para "corregir por partes"
        for key in ["1_secrets", "2_dependencies", "3_sast", "4_dast"]:
            if self.findings[key]:
                return key, self.findings[key]
        return None, []

def main():
    normalizer = SecurityNormalizer()
    
    # Recolección de todas las herramientas
    normalizer.process_trufflehog()
    normalizer.process_snyk()
    normalizer.process_semgrep()
    
    phase, issues = normalizer.get_priority_finding()
    
    if not phase:
        print("✅ PROYECTO LIMPIO: No se detectaron riesgos críticos.")
        sys.exit(0)

    # Exportamos los datos limpios para la IA (Paso 2)
    output = {
        "current_phase": phase,
        "total_issues_in_phase": len(issues),
        "findings": issues
    }
    
    with open('ia_context.json', 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    
    print(f"🚀 Fase Identificada: {phase}. Contexto generado en 'ia_context.json'.")

if __name__ == "__main__":
    main()