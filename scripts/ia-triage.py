import json
import sys
import os

def analyze_vulnerabilities(json_file):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # 1. Filtrar solo vulnerabilidades críticas o altas
        # Nota: Snyk puede devolver una lista o un objeto dependiendo del scan
        vulnerabilities = data.get('vulnerabilities', [])
        critical_issues = [v for v in vulnerabilities if v['severity'] in ['critical', 'high']]

        if not critical_issues:
            print("✅ IA Triage: No se detectaron vulnerabilidades críticas. ¡Buen trabajo!")
            return

        print(f"⚠️ IA Triage: Se encontraron {len(critical_issues)} vulnerabilidades de alto impacto.\n")

        # 2. Preparar el contexto para la IA (Prompt Engineering)
        # Aquí simulamos lo que enviaríamos a un LLM
        prompt_context = "Actúa como un experto en DevSecOps. Analiza estos fallos en un proyecto Java 21 y sugiere remediaciones basadas en 'Awesome Java Security':\n"
        
        for issue in critical_issues:
            summary = f"- [{issue['severity'].upper()}] {issue['title']} en {issue['packageName']}@{issue['version']}"
            print(summary)
            # Aquí podrías concatenar esto para enviarlo a una API de LLM
            
        print("\n💡 Sugerencia de IA: Actualiza las dependencias mencionadas en el pom.xml a sus versiones más recientes estables.")

    except FileNotFoundError:
        print(f"❌ Error: No se encontró el archivo {json_file}")
    except Exception as e:
        print(f"❌ Error procesando el reporte: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python ia-triage.py <reporte.json>")
    else:
        analyze_vulnerabilities(sys.argv[1])