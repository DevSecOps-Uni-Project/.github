import json
import os
import sys

def load_json_safely(file_path):
    """Carga archivos JSON manejando errores de formato y archivos faltantes."""
    if not os.path.exists(file_path):
        print(f"⚠️ Aviso: No se encontró el archivo {file_path}. Saltando análisis.")
        return None
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            if not content:
                return None
            # Si Snyk manda múltiples JSON o una lista, capturamos el objeto principal
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return data[0]
            return data
    except Exception as e:
        print(f"⚠️ Error procesando {file_path}: {e}")
        return None

def analyze_all():
    print("\n" + "="*55)
    print("🤖 IA SECURITY TRIAGE REPORT - PROYECTO IDS")
    print("Estándar: Awesome-DevSecOps | Java 21 LTS")
    print("="*55 + "\n")
    
    total_critical = 0
    summary = []

    # 1. ANÁLISIS SAST (Semgrep)
    # Corregido: Llamada a la función correcta 'load_json_safely'
    semgrep_data = load_json_safely('semgrep-results.json')
    if semgrep_data:
        results = semgrep_data.get('results', [])
        # Filtramos por severidad 'ERROR'
        s_crit = [r for r in results if r.get('extra', {}).get('severity') == 'ERROR']
        if s_crit:
            total_critical += len(s_crit)
            summary.append(f"🔍 SAST (Semgrep): {len(s_crit)} fallos críticos en lógica Java.")
            for r in s_crit[:5]: # Mostrar los primeros 5 para no saturar el log
                print(f"   [!] {r['path']}:{r['start']['line']} -> {r['extra']['message']}")

    # 2. ANÁLISIS SCA (Snyk)
    snyk_data = load_json_safely('snyk-results.json')
    if snyk_data:
        vulns = snyk_data.get('vulnerabilities', [])
        sn_crit = [v for v in vulns if v.get('severity') in ['critical', 'high']]
        if sn_crit:
            total_critical += len(sn_crit)
            summary.append(f"📦 SCA (Snyk): {len(sn_crit)} vulnerabilidades en pom.xml.")
            for v in sn_crit[:5]:
                print(f"   [!] {v['severity'].upper()}: {v['title']} en {v['packageName']}")

    # 3. ANÁLISIS CONTAINER (Trivy)
    trivy_data = load_json_safely('trivy-results.json')
    if trivy_data:
        results = trivy_data.get('Results', [])
        t_crit = 0
        for res in results:
            t_crit += len([v for v in res.get('Vulnerabilities', []) if v.get('Severity') in ['CRITICAL', 'HIGH']])
        if t_crit > 0:
            total_critical += t_crit
            summary.append(f"🐳 Container (Trivy): {t_crit} riesgos en la imagen Docker.")

    # --- CONCLUSIÓN FINAL ---
    print("\n" + "-"*40)
    print("📊 RESUMEN EJECUTIVO DE GOBERNANZA:")
    if not summary:
        print("  ✅ No se encontraron vulnerabilidades críticas.")
    else:
        for item in summary:
            print(f"  - {item}")
    print("-"*40)

    if total_critical > 0:
        print(f"\n❌ DECISIÓN IA: RECHAZADO (Blocked)")
        print(f"Motivo: Se detectaron {total_critical} hallazgos de alto riesgo.")
        print("💡 Acción: El pipeline de despliegue se ha detenido por seguridad.")
        sys.exit(1) 
    else:
        print("\n✅ DECISIÓN IA: APROBADO (Passed)")
        print("El proyecto cumple con los estándares mínimos de seguridad.")
        sys.exit(0)

if __name__ == "__main__":
    analyze_all()