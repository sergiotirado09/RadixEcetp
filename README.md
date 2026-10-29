# RADIxECETP

Portal académico con frontend HTML/CSS/JavaScript y backend local en Python conectado a MySQL en Aiven.

## Ejecutar el portal

1. Configura `.env` con estos cinco datos de **Aiven → servicio MySQL → Connection information**:
   - `DB_HOST`: Host
   - `DB_PORT`: Port
   - `DB_USER`: User
   - `DB_PASSWORD`: Password
   - `DB_NAME`: Database

   La conexión usa TLS y carga `ca.pem` si está en la carpeta del proyecto. No se necesitan más variables en `.env`.

2. Instala la dependencia e inicia el portal:

   ```powershell
   python -m pip install -r requirements.txt
   python main.py
   ```

`main.py` comprueba la conexión, inicia el sitio en `http://127.0.0.1:8765/` y abre ese enlace en el navegador. La terminal también muestra el enlace; detén el servidor con `Ctrl+C`.

El inicio de sesión usa las cuentas activas de la tabla `persona`. Los datos visibles y las operaciones de anotaciones, apelaciones y perfil se consultan o guardan en la base de Aiven. La tabla `notas` existente no relaciona sus registros con estudiantes, materias ni docentes: el administrador puede ver esos registros sin asociaciones inventadas, pero no se pueden publicar calificaciones individuales desde el portal.

El portal solo permite iniciar sesión con cuentas creadas por la institución. Para obtener una cuenta, solicítala al personal administrativo.

El administrador puede crear cuentas desde la sección **Base de datos interna**. Puede asignar uno de los perfiles institucionales; los datos se validan en el servidor y las contraseñas nuevas se guardan con PBKDF2. Al crear un estudiante también se crea su perfil de estudiante, sin grupo asignado.

## Importante

Esta integración es para pruebas locales: escucha solo en `127.0.0.1`. Las cuentas que ya existían en `persona` pueden tener contraseñas en texto plano; migra esas contraseñas a hashes seguros antes de usar datos reales o publicar el servicio.

No compartas ni subas `.env`, `ca.pem`, contraseñas ni volcados de base de datos a Git.
