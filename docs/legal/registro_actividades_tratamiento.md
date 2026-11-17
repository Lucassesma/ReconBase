# Registro de actividades de tratamiento (art. 30 RGPD)

Documento interno. No se publica. Revísalo cada vez que cambie lo que guarda la aplicación.

- **Responsable:** Lucas Sesma Vinck (NIF 53779442Z), Calle Doctor Aquilino Hurlé 22, 8.º A, 33202 Gijón (Asturias). hola@reconbase.es
- **Delegado de protección de datos:** no designado (no concurren los supuestos del art. 37 RGPD).
- **Última revisión:** 17 de noviembre de 2026.

Los plazos de conservación son los de `PLAZOS_CONSERVACION` en `server.py`. Los aplica cada día el cron `cron_retencion_datos`. La política de privacidad (`templates/privacy.html`) debe decir lo mismo.

## 1. Usuarios registrados

| Campo | Contenido |
|---|---|
| Finalidad | Prestar el servicio: cuenta, dominios, análisis, historial, monitorización, alertas, integraciones y API |
| Base jurídica | Ejecución del contrato (art. 6.1.b) |
| Interesados | Personas que crean una cuenta (normalmente profesionales y pymes) |
| Datos | Email, nombre de empresa, hash de la contraseña, preferencias, dominios y su verificación (fecha de la declaración de titularidad o autorización), escaneos, URL de Slack o webhook, clave de API, secreto 2FA, último acceso e IP |
| Destinatarios | Encargados: Railway (alojamiento en la UE), Cloudflare, Resend y Sentry (si está activo) |
| Transferencias | EE. UU. (Cloudflare, Resend, Sentry, posible soporte de Railway): Data Privacy Framework o cláusulas contractuales tipo |
| Conservación | Mientras exista la cuenta. La baja borra todo de inmediato (`_borrar_datos_usuario`) |
| Seguridad | TLS, hash de contraseñas con sal, 2FA opcional, acceso restringido a la BD, anti-SSRF en el escáner y límites de uso |

## 2. Seguridad de las cuentas (registro de accesos y actividad)

| Campo | Contenido |
|---|---|
| Finalidad | Detectar accesos indebidos y fuerza bruta, y auditar cambios en la cuenta |
| Base jurídica | Interés legítimo en la seguridad (art. 6.1.f) |
| Datos | Email del intento, IP, navegador, resultado y motivo (`login_attempts`); eventos de la cuenta con IP y navegador (`audit_logs`) |
| Conservación | 12 meses |

## 3. Comunicaciones comerciales a usuarios

| Campo | Contenido |
|---|---|
| Finalidad | Consejos de seguridad y novedades de ReconBase (onboarding y reenganche) |
| Base jurídica | Interés legítimo y art. 21.2 LSSI (clientes, productos propios similares). Posibilidad de oposición en el registro, en el perfil y en cada email (enlace firmado `/baja/<token>`) |
| Datos | Email, preferencia (`users.acepta_comercial`) y fecha de la última modificación |
| Conservación | Mientras exista la cuenta |

## 4. Informes por email pedidos sin cuenta (leads)

| Campo | Contenido |
|---|---|
| Finalidad | Enviar el informe pedido y, solo con consentimiento, dos emails de seguimiento |
| Base jurídica | Medidas a petición del interesado (informe) y consentimiento (seguimiento; casilla desmarcada por defecto) |
| Datos | Email, dominio y resultado del análisis pasivo, consentimiento y su fecha, navegador, IP seudonimizada (HMAC con clave diaria) |
| Conservación | Sin consentimiento: 90 días. Con consentimiento: 2 años. Dados de baja: 30 días |

## 5. Uso de las herramientas gratuitas

| Campo | Contenido |
|---|---|
| Finalidad | Estadísticas de uso y prevención de abusos |
| Base jurídica | Interés legítimo (art. 6.1.f) |
| Datos | Dominio analizado, resultado, referer, navegador (truncado), IP seudonimizada con clave diaria (`anonymous_scans`) |
| Conservación | 12 meses |

## 6. Analítica web

| Campo | Contenido |
|---|---|
| Finalidad | Medir el uso de la web |
| Base jurídica | Plausible (sin cookies ni identificadores): interés legítimo. Google Analytics: consentimiento (cookies, art. 22.2 LSSI) |
| Destinatarios | Plausible Insights OÜ (UE); Google Ireland (con posible transferencia a EE. UU., Data Privacy Framework) |
| Conservación | La de cada proveedor. Cookies `_ga`: hasta 2 años, solo con consentimiento |

## 7. Exclusión de dominios del escáner

| Campo | Contenido |
|---|---|
| Finalidad | Respetar la petición del titular de que su dominio no se analice |
| Base jurídica | Interés legítimo y atención de la oposición |
| Datos | Dominio, email de contacto del dominio, fechas de petición y confirmación (`scan_opt_outs`) |
| Conservación | Sin confirmar: 30 días. Confirmadas: mientras deban respetarse |

## 8. Datos de terceros que aparecen en los análisis

| Campo | Contenido |
|---|---|
| Finalidad | Informar al usuario del estado de seguridad de su dominio |
| Base jurídica | Interés legítimo del usuario, titular o autorizado (art. 6.1.f) |
| Datos | Información técnica pública. Solo en dominios verificados: nombres públicos de autores de WordPress (saneados, máximo 5). HIBP: solo el email propio del usuario o emails de dominios verificados |
| Destinatarios | Have I Been Pwned (Australia; art. 49.1.b RGPD, a petición del usuario). Google Web Risk recibe solo nombres de dominio |
| Conservación | Dentro del escaneo del usuario; se borra con él o con la cuenta |
| Medidas | Los ficheros sensibles se sondean sin descargar su contenido (`sondear_fichero`); análisis activos solo en dominios verificados |

## 9. Facturas de suscripciones anteriores

| Campo | Contenido |
|---|---|
| Finalidad | Cumplir obligaciones mercantiles y fiscales de las suscripciones cobradas cuando ReconBase era de pago |
| Base jurídica | Obligación legal (art. 6.1.c) |
| Datos | Número, concepto, importe, fechas, email y nombre del cliente (se conservan aunque el cliente borre su cuenta) |
| Conservación | Plazos de la normativa mercantil y tributaria (consúltalos con tu gestor) |

## Pendiente o a revisar

- Firmar o aceptar los contratos de encargo (DPA) de Railway, Cloudflare, Resend, Plausible, Google y Sentry. Normalmente se aceptan en el panel de cada proveedor.
- Si se añade un proveedor o un dato nuevo, actualizar este documento y la política de privacidad.
