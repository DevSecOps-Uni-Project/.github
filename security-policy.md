# Security Policy - DevSecOps-Uni-Project 🛡️

Esta política define los estándares de seguridad, reporte y remediación para todos los proyectos de la organización, integrando principios de **Awesome DevSecOps** y auditoría asistida por **IA**.

## 1. Versiones Compatibles
Actualmente, solo se brinda soporte de seguridad a las siguientes versiones de nuestro stack principal:

| Tecnología | Versión Soportada | Estado |
| :--- | :--- | :--- |
| **Java** | 21 (LTS) | ✅ Activa |
| **Spring Boot** | 3.x | ✅ Activa |
| **Python (Scripts)** | 3.10+ | ✅ Activa |

## 2. Estándares de "Awesome" Gobernanza
Nuestros procesos de CI/CD se rigen por las mejores prácticas documentadas en la comunidad **Awesome**:
*   **SCA (Software Composition Analysis):** Ningún proyecto puede pasar a producción con vulnerabilidades de severidad `High` o `Critical` en sus dependencias (basado en el estándar de *Awesome-SAST*).
*   **Clean Code:** Se exige un cumplimiento del 0% de issues en SonarQube para el código fuente (SAST).
*   **Secret Management:** Queda estrictamente prohibido el hardcoding de credenciales. Se utiliza *Secret Scanning* automático.

## 3. Reporte de Vulnerabilidades
Si encuentras una vulnerabilidad, por favor **no abras un Issue público**. Sigue este proceso:
1.  Utiliza la función de **"Private Vulnerability Reporting"** en la pestaña de Seguridad del repositorio afectado.
2.  Incluye un PoC (Proof of Concept) y los pasos para reproducir el hallazgo.
3.  Nuestro equipo de gobernanza (asistido por el script de **IA-Triage**) responderá en un plazo de 48 horas.

## 4. Remediación Asistida por IA
Para agilizar la respuesta, la organización utiliza modelos de IA para:
*   **Triaje Automático:** Categorización de hallazgos según impacto.
*   **Sugerencia de Parches:** Generación automática de pull requests para actualizar dependencias vulnerables.

## 5. Compromiso de Calidad
Cada commit debe seguir el estándar de **Conventional Commits**. Los parches de seguridad deben usar el tipo `fix(security):` para su correcta trazabilidad en los logs de auditoría.