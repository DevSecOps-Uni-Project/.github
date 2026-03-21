import json
import os
import sys

def load_json_safely(file_path):
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content: return None
            
            # Si Snyk pegó varios JSONs, intentamos rescatar el primero válido
            if content.startswith('[') or content.startswith('{'):
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    # Buscamos el final del primer objeto JSON válido
                    import re
                    match = re.search(r'({[\s\S]*?\n})', content)
                    if match:
                        return json.loads(match.group(1))
            return json.loads(content)
    except Exception as e:
        print(f"⚠️ Error procesando {file_path}: {e}")
        return None

def analyze_all():
    print("\n" + "="*55)
    print("🤖 IA SECURITY TRIAGE REPORT - PROYECTO IDS")
    print("Estándar: SARIF Compliance | Java 21 LTS")

    repo_name = os.getenv('GITHUB_REPOSITORY', 'Proyecto Local')
    print(f"📌 Target: {repo_name}")
    print("="*55 + "\n")
    
    total_critical = 0
    summary = []

    # 1. ANÁLISIS SAST (Semgrep - SARIF)
    semgrep_data = load_json_safely('semgrep-results.sarif')
    if semgrep_data:
        # En SARIF, los hallazgos están en runs[0].results
        runs = semgrep_data.get('runs', [])
        if runs:
            results = runs[0].get('results', [])
            # En SARIF 'error' equivale a crítico/alto
            s_crit = [r for r in results if r.get('level') == 'error']
            if s_crit:
                total_critical += len(s_crit)
                summary.append(f"🔍 SAST (Semgrep): {len(s_crit)} fallos críticos en lógica.")
                for r in s_crit[:3]:
                    msg = r.get('message', {}).get('text', 'Sin descripción')
                    loc = r.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'unknown')
                    line = r.get('locations', [{}])[0].get('physicalLocation', {}).get('region', {}).get('startLine', '?')
                    print(f"   [!] {loc}:{line} -> {msg[:80]}...")

    # 2. ANÁLISIS SCA (Snyk - Sigue siendo JSON)
    snyk_data = load_json_safely('snyk-results.json')
    if snyk_data:
        vulns = snyk_data.get('vulnerabilities', [])
        sn_crit = [v for v in vulns if v.get('severity') in ['critical', 'high']]
        if sn_crit:
            total_critical += len(sn_crit)
            summary.append(f"📦 SCA (Snyk): {len(sn_crit)} vulnerabilidades en dependencias.")

    # 3. ANÁLISIS CONTAINER (Trivy - SARIF)
    trivy_data = load_json_safely('trivy-results.sarif')
    if trivy_data:
        runs = trivy_data.get('runs', [])
        if runs:
            results = runs[0].get('results', [])
            # Filtramos por reglas que tengan severidad alta en sus metadatos o nivel 'error'
            t_crit = len([r for r in results if r.get('level') in ['error', 'warning']])
            if t_crit > 0:
                total_critical += t_crit
                summary.append(f"🐳 Container (Trivy): {t_crit} riesgos detectados en la imagen.")

    # --- CONCLUSIÓN FINAL ---
    print("\n" + "-"*40)
    print("📊 RESUMEN EJECUTIVO DE GOBERNANZA:")
    if not summary:
        print("   ✅ No se encontraron vulnerabilidades críticas.")
    else:
        for item in summary:
            print(f"   - {item}")
    print("-"*40)

    if total_critical > 0:
        print(f"\n❌ DECISIÓN IA: RECHAZADO (Blocked)")
        print(f"Motivo: {total_critical} hallazgos de riesgo.")
        sys.exit(1) 
    else:
        print("\n✅ DECISIÓN IA: APROBADO (Passed)")
        sys.exit(0)

if __name__ == "__main__":
    analyze_all()