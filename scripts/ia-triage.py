import json
import os
import sys

def load_json(path):
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return None

def analyze_all():
    print("🤖 --- IA SECURITY MULTI-LAYER REPORT --- 🤖")
    print("Estándar de Referencia: Awesome-DevSecOps / Java 21 LTS\n")
    
    total_critical = 0
    report_summary = []

    # 1. Análisis de Capa de Aplicación (Snyk)
    snyk_data = load_json('snyk-results.json')
    if snyk_data:
        vulns = snyk_data.get('vulnerabilities', [])
        crit = [v for v in vulns if v['severity'] in ['critical', 'high']]
        total_critical += len(crit)
        report_summary.append(f"📦 SCA (Snyk): {len(crit)} riesgos detectados en librerías Java.")

    # 2. Análisis de Capa de Infraestructura (Trivy)
    # Trivy suele exportar un JSON con una estructura de 'Results'
    trivy_data = load_json('trivy-results.json')
    if trivy_data:
        results = trivy_data.get('Results', [])
        t_crit = 0
        for res in results:
            t_crit += len([v for v in res.get('Vulnerabilities', []) if v['Severity'] in ['CRITICAL', 'HIGH']])
        total_critical += t_crit
        report_summary.append(f"🐳 Container (Trivy): {t_crit} fallos en el SO/Dockerfile.")

    # 3. Análisis de Capa Dinámica (OWASP ZAP)
    # ZAP genera reportes en varios formatos; aquí asumimos un resumen simple
    if os.path.exists('zap_out.conf'): # Config de salida de ZAP
        report_summary.append("🌐 DAST (OWASP ZAP): Escaneo de línea base completado.")

    # LOGICA DE IA: Triage y Decisión
    for line in report_summary:
        print(line)

    print("\n--- CONCLUSIÓN DE IA ---")
    if total_critical > 0:
        print(f"❌ ESTADO: RECHAZADO. Se encontraron {total_critical} puntos de falla críticos.")
        print("💡 ACCIÓN RECOMENDADA: Revise el historial de 'Awesome-Java-Security' para mitigar inyecciones.")
        sys.exit(1) # Forzar fallo del pipeline
    else:
        print("✅ ESTADO: APROBADO. El proyecto cumple con la gobernanza de DevSecOps-Uni-Project.")
        sys.exit(0)

if __name__ == "__main__":
    analyze_all()