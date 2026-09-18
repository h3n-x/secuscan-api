# Propuesta de Proyecto

## Título

**SecuScan API: Plataforma SaaS para el Escaneo Automatizado de Seguridad Perimetral en Dominios e IPs**

---

## Planteamiento del Problema

La exposición de servicios en internet —sitios web, APIs, servidores de correo, subdominios de desarrollo— crece constantemente, tanto en empresas como en proyectos personales y académicos. Sin embargo, gran parte de quienes administran esta infraestructura (desarrolladores independientes, pequeñas empresas, estudiantes, comunidades técnicas) no cuentan con procesos sistemáticos para verificar su postura de seguridad básica: puertos innecesariamente abiertos, cabeceras HTTP mal configuradas, certificados TLS/SSL vencidos o débiles, y configuraciones DNS que facilitan suplantación de dominio o exfiltración de información (falta de SPF/DKIM/DMARC, zone transfers abiertos, etc.).

Las herramientas que permiten detectar estos problemas existen (Nmap, testssl.sh, SecurityHeaders.com, Qualys SSL Labs, Shodan), pero están fragmentadas, requieren conocimiento técnico para interpretarlas en conjunto, o son parte de suites empresariales costosas orientadas a organizaciones grandes. Esto deja un vacío para quien necesita una evaluación rápida, unificada y comprensible de su propia superficie de ataque expuesta.

## Descripción de la Situación Actual

Actualmente, verificar la seguridad perimetral de un dominio o servidor implica ejecutar manualmente varias herramientas distintas (una para puertos, otra para TLS, otra para headers, otra para DNS), consolidar los resultados a mano, y tener el criterio técnico para priorizar qué hallazgos son realmente relevantes. Esto es lento, propenso a omisiones, y poco accesible para quien no se dedica profesionalmente a la ciberseguridad.

Proyectos personales, comunidades (como servidores de juegos, bots, aplicaciones web pequeñas) y estudiantes de programación suelen desplegar servicios en la nube sin una revisión de seguridad formal, quedando expuestos a escaneos automatizados maliciosos, certificados vencidos sin aviso, o cabeceras HTTP que facilitan ataques como clickjacking o XSS.

## Formulación del Problema

**¿Cómo se puede diseñar e implementar una plataforma tipo SaaS que centralice y automatice la evaluación de vulnerabilidades superficiales (puertos abiertos, cabeceras HTTP inseguras, certificados TLS/SSL y configuraciones DNS débiles) de un dominio o dirección IP, entregando reportes claros y accionables sin requerir conocimientos avanzados de ciberseguridad por parte del usuario?**

## Sistematización del Problema

1. ¿Qué verificaciones de seguridad perimetral (puertos, headers, TLS/SSL, DNS) tienen mayor impacto y relevancia para detectar exposiciones comunes en servicios de baja y mediana complejidad?
2. ¿Qué arquitectura técnica permite ejecutar estos escaneos de forma asíncrona y escalable, sin saturar el servidor ni generar tráfico que pueda interpretarse como actividad maliciosa?
3. ¿Cómo debe estructurarse y priorizarse la información en el reporte final para que resulte comprensible tanto para usuarios técnicos como no técnicos?
4. ¿Qué mecanismos de autenticación, control de abuso (rate limiting) y verificación de autorización sobre el objetivo son necesarios para evitar que la plataforma se utilice para escanear infraestructura de terceros sin consentimiento?

## Justificación

**Académica:** el proyecto integra conocimientos de desarrollo backend (Python, FastAPI, arquitecturas asíncronas) con fundamentos de ciberseguridad (reconocimiento, hardening, criptografía aplicada a TLS), consolidando de forma práctica contenidos vistos en la formación en Ingeniería de Sistemas y en la certificación profesional en Ciberseguridad de Google.

**Práctica/profesional:** construye un artefacto de portafolio verificable en producción, demostrando la capacidad de diseñar un servicio real, desplegado, con consideraciones de seguridad y arquitectura — un diferencial relevante frente a proyectos puramente académicos o de práctica local.

**Social:** ofrece una herramienta accesible para que desarrolladores independientes, pequeñas comunidades y estudiantes puedan evaluar su propia exposición en internet sin necesidad de contratar servicios de seguridad empresariales costosos.

**Tecnológica:** permite explorar y aplicar buenas prácticas de arquitectura de software (desacoplamiento de módulos de escaneo, ejecución asíncrona, contenerización con Docker, despliegue en infraestructura cloud real sobre DigitalOcean).

## Objetivo General

Diseñar e implementar una plataforma SaaS basada en FastAPI que automatice el escaneo de seguridad perimetral —puertos, cabeceras HTTP, certificados TLS/SSL y configuración DNS— de dominios e IPs, generando reportes claros, priorizados y accionables para usuarios con y sin formación técnica en ciberseguridad.

## Objetivos Específicos

1. Desarrollar los módulos de escaneo (puertos, cabeceras HTTP, TLS/SSL y DNS) como servicios independientes y desacoplados dentro de la arquitectura backend, permitiendo su ejecución y mantenimiento de forma aislada.
2. Implementar un sistema de ejecución asíncrona de escaneos con autenticación de usuarios, límites de uso (rate limiting) y un mecanismo de verificación de autorización sobre el dominio/IP objetivo antes de permitir el escaneo.
3. Diseñar e implementar un motor de generación de reportes que traduzca los hallazgos técnicos en información priorizada y comprensible, desplegado en un entorno de producción sobre un Droplet de DigitalOcean mediante contenedores Docker.

## Marco de Referencia / Antecedentes

Existen herramientas y servicios de referencia directa para este proyecto, cada uno cubriendo una porción del problema:

- **Nmap:** referente histórico en escaneo de puertos y detección de servicios, usado como base conceptual para el módulo de escaneo de puertos.
- **Qualys SSL Labs / testssl.sh:** herramientas especializadas en el análisis de configuración TLS/SSL, evaluando versiones de protocolo, cifrados soportados y validez de certificados.
- **SecurityHeaders.com / Mozilla Observatory:** servicios enfocados en analizar cabeceras HTTP de seguridad (CSP, HSTS, X-Frame-Options, entre otras) y calificar su robustez.
- **Shodan:** motor de búsqueda de dispositivos e infraestructura expuesta en internet, referente en el concepto de reconocimiento pasivo a gran escala.
- **OWASP ZAP:** proyecto de código abierto orientado al análisis de vulnerabilidades en aplicaciones web, referente en buenas prácticas de escaneo ético y automatizado.

Como antecedente propio, el repositorio `repo-secret-auditor` desarrollado previamente por el autor auditaba código fuente en busca de secretos expuestos (credenciales, tokens) de forma local. SecuScan API representa una evolución de ese enfoque: de un script de auditoría estática de código a un servicio web que audita infraestructura en vivo.

## Marco Teórico

- **Reconocimiento de seguridad (Security Reconnaissance):** fase inicial de evaluación de seguridad centrada en recopilar información sobre un objetivo sin explotar vulnerabilidades, distinguiéndose entre reconocimiento pasivo (sin interacción directa, ej. consultas DNS/WHOIS) y activo (interacción directa, ej. escaneo de puertos).
- **Escaneo de puertos:** técnica para identificar qué puertos TCP/UDP de un host están abiertos, cerrados o filtrados, permitiendo inferir qué servicios están expuestos.
- **Cabeceras HTTP de seguridad:** directivas incluidas en las respuestas HTTP (como `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`) que instruyen al navegador para mitigar ataques como clickjacking, XSS o sniffing de contenido.
- **TLS/SSL y certificados digitales:** protocolos criptográficos que garantizan confidencialidad e integridad en las comunicaciones; su mala configuración (protocolos obsoletos, certificados expirados o autofirmados) constituye una vulnerabilidad común.
- **Seguridad en DNS:** mecanismos como SPF, DKIM y DMARC previenen la suplantación de dominio en correos electrónicos; una configuración débil facilita ataques de phishing bajo el nombre del dominio afectado.
- **Arquitectura orientada a servicios y ejecución asíncrona:** patrón de diseño donde cada módulo de escaneo se ejecuta de forma independiente y no bloqueante, permitiendo escalabilidad y aislamiento de fallos.
- **Ética y legalidad del escaneo:** principio fundamental de que solo debe escanearse infraestructura sobre la cual se tiene autorización explícita, dado que el escaneo no autorizado puede constituir una actividad ilegal en la mayoría de jurisdicciones.

## Metodología

El proyecto se desarrollará bajo un enfoque de **investigación aplicada**, con una metodología de desarrollo de software **ágil e incremental** (inspirada en Scrum), estructurada en las siguientes fases:

1. **Fase de investigación y análisis:** estudio de herramientas de referencia, definición de los checks de seguridad a implementar y sus criterios de evaluación.
2. **Fase de diseño:** definición de la arquitectura del sistema, modelo de datos, contratos de API (endpoints) y diagrama de componentes (módulos de escaneo, cola de tareas, base de datos, capa de autenticación).
3. **Fase de desarrollo iterativo:** construcción de cada módulo de escaneo como incremento independiente y funcional, con integración continua al backend principal (FastAPI).
4. **Fase de pruebas:** pruebas unitarias por módulo, pruebas de integración sobre dominios controlados/propios, y pruebas de carga básicas sobre la ejecución asíncrona.
5. **Fase de despliegue:** contenerización con Docker y despliegue en un Droplet de DigitalOcean, incluyendo configuración de HTTPS, variables de entorno y monitoreo básico.
6. **Fase de evaluación:** validación de los objetivos específicos mediante pruebas sobre entornos propios y recolección de retroalimentación sobre la claridad de los reportes generados.

## Variables y Operacionalización

| Variable | Tipo | Definición conceptual | Definición operacional | Indicadores |
|---|---|---|---|---|
| Implementación de la plataforma de escaneo automatizado | Independiente | Existencia y funcionamiento del sistema SecuScan API como servicio desplegado | Disponibilidad del servicio vía API/endpoint accesible en producción | Uptime del servicio (%), número de módulos de escaneo activos |
| Nivel de visibilidad de la postura de seguridad perimetral | Dependiente | Grado de conocimiento que obtiene un usuario sobre las debilidades expuestas de su dominio/IP | Cantidad y calidad de hallazgos reportados tras un escaneo | N.º de hallazgos detectados por categoría (puertos, headers, TLS, DNS) |
| Tiempo de ejecución del escaneo | Dependiente | Duración del proceso de análisis desde la solicitud hasta el reporte final | Medición en segundos desde el inicio hasta la finalización del escaneo asíncrono | Tiempo promedio de escaneo (s) |
| Precisión de los hallazgos | Dependiente | Correspondencia entre lo reportado por la plataforma y el estado real del objetivo evaluado | Comparación de resultados contra herramientas de referencia (Nmap, testssl.sh) sobre los mismos objetivos de prueba | Tasa de falsos positivos/negativos (%) |
| Usabilidad del reporte | Dependiente | Facilidad con la que un usuario sin formación técnica interpreta el resultado del escaneo | Evaluación cualitativa de claridad y priorización del reporte generado | Escala de claridad percibida (1-5), tiempo de comprensión del reporte |
| Control de abuso y autorización | Independiente | Mecanismos que impiden el uso de la plataforma sobre objetivos no autorizados | Verificación de propiedad del dominio/IP antes de habilitar el escaneo, límites de solicitudes por usuario | N.º de intentos bloqueados por falta de autorización, límite de requests/hora respetado |

---

## Alcance y Limitaciones

- El proyecto se limita a checks de **seguridad perimetral pasiva/semi-activa** (puertos, headers, TLS, DNS); no incluye explotación de vulnerabilidades ni pruebas de penetración activas.
- Solo se permitirá el escaneo de dominios/IPs sobre los cuales el usuario declare y, en la medida de lo posible, verifique autorización (ej. mediante un registro TXT de verificación en el DNS del dominio).
- La primera versión (MVP) no contempla multi-tenancy avanzado ni facturación; se enfoca en validar la arquitectura técnica y la calidad de los reportes.
