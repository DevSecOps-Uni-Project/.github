import json
import os
import sys

def load_json_safely(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            # Si Snyk manda múltiples JSON, intentamos capturar solo el primero
            if content.startswith('['):
                return json.loads(content)[0]
            return json.loads(content)
    except Exception as e:
        print(f"⚠️ Error procesando {file_path}: {e}")
        return None

def analyze_all():
    print("\n" + "="*50)
    print("🤖 IA SECURITY TRIAGE REPORT - PROYECTO IDS")
    print("Estándar: Awesome-DevSecOps | Java 21 LTS")
    print("="*50 + "\n")
    
    total_critical = 0
    summary = []

    # 1. ANÁLISIS SAST (Semgrep - Lógica de Código Java)
    semgrep_data = load_json('semgrep-results.json')
    if semgrep_data:
        results = semgrep_data.get('results', [])
        # Filtramos por severidad 'ERROR' (Crítico en Semgrep)
        s_crit = [r for r in results if r['extra']['severity'] == 'ERROR']
        total_critical += len(s_crit)
        summary.append(f"🔍 SAST (Semgrep): {len(s_crit)} fallos de lógica/seguridad en código Java.")
        for r in s_crit:
            print(f"  [!] {r['path']}:{r['start']['line']} -> {r['extra']['message']}")

    # 2. ANÁLISIS SCA (Snyk - Librerías y Dependencias)
    snyk_data = load_json('snyk-results.json')
    if snyk_data:
        vulns = snyk_data.get('vulnerabilities', [])
        # Snyk reporta criticidad como 'critical' o 'high'
        sn_crit = [v for v in vulns if v['severity'] in ['critical', 'high']]
        total_critical += len(sn_crit)
        summary.append(f"📦 SCA (Snyk): {len(sn_crit)} vulnerabilidades en pom.xml.")
        for v in sn_crit:
            print(f"  [!] {v['severity'].upper()}: {v['title']} en {v['packageName']}")

    # 3. ANÁLISIS CONTAINER (Trivy - Docker e Infra base)
    trivy_data = load_json('trivy-results.json')
    if trivy_data:
        results = trivy_data.get('Results', [])
        t_crit = 0
        for res in results:
            t_crit += len([v for v in res.get('Vulnerabilities', []) if v['Severity'] in ['CRITICAL', 'HIGH']])
        total_critical += t_crit
        summary.append(f"🐳 Container (Trivy): {t_crit} riesgos en la imagen Docker.")

    # --- CONCLUSIÓN FINAL ---
    print("\n" + "-"*30)
    print("📊 RESUMEN EJECUTIVO:")
    for item in summary:
        print(f"  - {item}")
    print("-"*30)

    if total_critical > 0:
        print(f"\n❌ DECISIÓN IA: RECHAZADO (Blocked)")
        print(f"Motivo: Se detectaron {total_critical} hallazgos de alto riesgo que violan la gobernanza.")
        print("💡 Sugerencia: Revise los 'Details' en GitHub Actions para aplicar los parches.")
        sys.exit(1) # Finaliza el pipeline con error
    else:
        print("\n✅ DECISIÓN IA: APROBADO (Passed)")
        print("El código y las dependencias cumplen con los umbrales de seguridad establecidos.")
        sys.exit(0) # Finaliza el pipeline con éxito

if __name__ == "__main__":
    analyze_all()