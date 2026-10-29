"""Inicia el portal académico local conectado a MySQL en Aiven."""

from __future__ import annotations

import hashlib
import hmac
import http.cookies
import json
import os
import secrets
import ssl
import sys
import threading
import webbrowser
from datetime import datetime, timedelta
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

try:
    import pymysql
    from pymysql.cursors import DictCursor
except ImportError:
    print("Falta PyMySQL. Instálalo con: python -m pip install -r requirements.txt")
    raise SystemExit(1)


ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
HOST = "127.0.0.1"
PORT = 8765
SESSION_SECONDS = 8 * 60 * 60
MAX_REQUEST_BYTES = 20 * 1024
PASSWORD_HASH_ITERATIONS = 600_000
MAX_DOCUMENT_NUMBER = 9_223_372_036_854_775_807
ALLOWED_ROLES = {"Administrador", "Docente", "Estudiante"}
ACCOUNT_ROLES = {"Administrador", "Docente", "Estudiante", "Coordinador", "Rector"}
STAFF_ROLES = {"Administrador", "Coordinador", "Rector"}
APPEAL_STATES = {"Aprobada", "Rechazada", "En Revisión"}
ANNOTATION_TYPES = {"Tipo 1 - Leve", "Tipo 2 - Grave", "Tipo 3 - Gravísima"}


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values

    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if not separator or not key.strip():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def get_setting(name: str, file_values: dict[str, str]) -> str:
    return os.environ.get(name) or file_values.get(name, "")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return (
        f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}"
        f"${salt.hex()}${derived.hex()}"
    )


def verify_password(stored_password: str, password: str) -> bool:
    if stored_password.startswith("pbkdf2_sha256$"):
        try:
            algorithm, iterations, salt_hex, expected_hex = stored_password.split("$")
            if algorithm != "pbkdf2_sha256":
                return False
            actual = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt_hex),
                int(iterations),
            )
            return hmac.compare_digest(actual.hex(), expected_hex)
        except (ValueError, TypeError):
            return False
    return hmac.compare_digest(
        stored_password.encode("utf-8"), password.encode("utf-8")
    )


def open_database(file_values: dict[str, str]):
    context = ssl.create_default_context()
    context.check_hostname = True
    ca_file = ROOT / "ca.pem"
    if ca_file.is_file():
        context.load_verify_locations(cafile=str(ca_file))

    return pymysql.connect(
        host=get_setting("DB_HOST", file_values),
        port=int(get_setting("DB_PORT", file_values)),
        user=get_setting("DB_USER", file_values),
        password=get_setting("DB_PASSWORD", file_values),
        database=get_setting("DB_NAME", file_values),
        charset="utf8mb4",
        ssl=context,
        cursorclass=DictCursor,
        connect_timeout=10,
        read_timeout=10,
        write_timeout=10,
        autocommit=False,
    )


def public_user(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "documento": str(row["documento"]) if row.get("documento") is not None else "",
        "nombre": row["nombre"],
        "correo": row.get("correo") or "",
        "telefono": row.get("telefono") or "",
        "rol": row["rol"],
        "estado": row.get("estado", "Activo"),
        "grupo": row.get("grupo") or "",
        "grupoId": row.get("grupoId"),
        "acudiente": row.get("acudiente") or "",
        "parentesco": row.get("parentesco") or "",
    }


def load_portal_data(user: dict, file_values: dict[str, str]) -> dict:
    role = user["rol"]
    user_id = int(user["id"])
    if role not in ALLOWED_ROLES:
        raise PermissionError("Este perfil aún no está habilitado para acceder al portal.")
    is_staff = role in STAFF_ROLES
    is_teacher = role == "Docente"
    is_student = role == "Estudiante"

    with open_database(file_values) as connection:
        with connection.cursor() as cursor:
            person_query = """
                SELECT p.id_persona AS id,
                       CAST(p.documento_identidad AS CHAR) AS documento,
                       TRIM(CONCAT_WS(' ', p.nombre_1, p.nombre_2, p.apellido_1, p.apellido_2)) AS nombre,
                       p.correo_electronico AS correo, p.telefono, p.rol, p.estado,
                       e.nombre_completo_acudiente AS acudiente,
                       e.parentezco_acudiente AS parentesco,
                       COALESCE(
                           (SELECT m.id_grupo FROM matricula m
                            WHERE m.id_persona = p.id_persona
                            ORDER BY m.anio_lectivo DESC LIMIT 1),
                           e.id_grupo
                       ) AS grupoId,
                       g.nombre_grupo AS grupo
                FROM persona p
                LEFT JOIN estudiante e ON e.id_persona = p.id_persona
                LEFT JOIN grupo g ON g.id_grupo = COALESCE(
                    (SELECT m.id_grupo FROM matricula m
                     WHERE m.id_persona = p.id_persona
                     ORDER BY m.anio_lectivo DESC LIMIT 1),
                    e.id_grupo
                )
            """
            if is_student:
                cursor.execute(person_query + " WHERE p.id_persona = %s", (user_id,))
            elif is_teacher:
                cursor.execute(
                    person_query + " WHERE p.rol IN ('Estudiante', 'Docente')"
                )
            else:
                cursor.execute(person_query)
            users = [public_user(row) for row in cursor.fetchall()]

            if is_teacher:
                assignment_filter = "WHERE a.id_persona = %s"
                assignment_params = (user_id,)
            elif is_student:
                assignment_filter = """
                    WHERE a.id_grupo = COALESCE(
                        (SELECT m.id_grupo FROM matricula m
                         WHERE m.id_persona = %s ORDER BY m.anio_lectivo DESC LIMIT 1),
                        (SELECT e.id_grupo FROM estudiante e
                         WHERE e.id_persona = %s LIMIT 1)
                    )
                """
                assignment_params = (user_id, user_id)
            else:
                assignment_filter = ""
                assignment_params = ()

            cursor.execute(
                f"""
                SELECT a.`id_asignación` AS id, a.id_persona AS teacherId,
                       a.id_materia AS subjectId, a.id_grupo AS groupId,
                       ma.nombre_materia AS subjectName,
                       ma.intensidad_horaria AS intensidad,
                       g.nombre_grupo AS groupName, g.grado,
                       TRIM(CONCAT_WS(' ', p.nombre_1, p.nombre_2,
                           p.apellido_1, p.apellido_2)) AS teacherName
                FROM asignacion a
                JOIN materia ma ON ma.id_materia = a.id_materia
                JOIN grupo g ON g.id_grupo = a.id_grupo
                JOIN persona p ON p.id_persona = a.id_persona
                {assignment_filter}
                ORDER BY g.grado, ma.nombre_materia
                """,
                assignment_params,
            )
            assignment_rows = cursor.fetchall()

            if is_staff:
                cursor.execute("SELECT id_grupo AS id, nombre_grupo AS nombre, grado FROM grupo ORDER BY grado, nombre_grupo")
                groups = cursor.fetchall()
            elif is_teacher:
                groups = list({
                    int(row["groupId"]): {
                        "id": int(row["groupId"]),
                        "nombre": row["groupName"],
                        "grado": int(row["grado"]),
                    }
                    for row in assignment_rows
                }.values())
            else:
                groups = list({
                    int(row["groupId"]): {
                        "id": int(row["groupId"]),
                        "nombre": row["groupName"],
                        "grado": int(row["grado"]),
                    }
                    for row in assignment_rows
                }.values())

            subjects = list({
                int(row["subjectId"]): {
                    "id": int(row["subjectId"]),
                    "nombre": row["subjectName"],
                    "intensidad": int(row["intensidad"]),
                    "docenteId": int(row["teacherId"]),
                    "grupoId": int(row["groupId"]),
                }
                for row in assignment_rows
            }.values())
            assignments = [
                {
                    "id": int(row["id"]),
                    "teacherId": int(row["teacherId"]),
                    "subjectId": int(row["subjectId"]),
                    "groupId": int(row["groupId"]),
                }
                for row in assignment_rows
            ]

            if is_teacher:
                annotation_filter = "WHERE a.id_docente = %s"
                annotation_params = (user_id,)
            elif is_student:
                annotation_filter = "WHERE e.id_persona = %s"
                annotation_params = (user_id,)
            else:
                annotation_filter = ""
                annotation_params = ()

            cursor.execute(
                f"""
                SELECT a.id_anotacion AS id, e.id_persona AS studentId,
                       a.id_docente AS teacherId,
                       DATE_FORMAT(a.fecha_hora, '%%Y-%%m-%%dT%%H:%%i') AS fecha,
                       a.tipo_falta AS tipo, a.descripcion_anotacion AS descripcion,
                       a.version_estudiante AS version, a.estado_apelacion AS estado
                FROM anotaciones a
                JOIN estudiante e ON e.id_estudiante = a.id_estudiante
                {annotation_filter}
                ORDER BY a.fecha_hora DESC
                """,
                annotation_params,
            )
            annotations = [
                {
                    **row,
                    "id": int(row["id"]),
                    "studentId": int(row["studentId"]),
                    "teacherId": int(row["teacherId"]) if row["teacherId"] is not None else None,
                    "version": row["version"] or "",
                }
                for row in cursor.fetchall()
            ]

            grades = []
            if is_staff:
                cursor.execute(
                    """
                    SELECT id_nota AS id, calficacion AS calificacion,
                           autoevaluacion, coevalucion AS coevaluacion,
                           total, estado, descripcion
                    FROM notas
                    ORDER BY id_nota
                    """
                )
                grades = [
                    {
                        "id": int(row["id"]),
                        "calificacion": float(row["calificacion"] or 0),
                        "autoevaluacion": float(row["autoevaluacion"] or 0),
                        "coevaluacion": float(row["coevaluacion"] or 0),
                        "total": float(row["total"] or 0),
                        "estado": row["estado"],
                        "descripcion": row["descripcion"],
                    }
                    for row in cursor.fetchall()
                ]

    return {
        "users": users,
        "groups": groups,
        "subjects": subjects,
        "assignments": assignments,
        # La tabla existente notas no relaciona sus filas con estudiantes,
        # materias ni docentes; solo el personal puede ver sus campos tal cual.
        "grades": grades,
        "annotations": annotations,
    }


def serialize_json(value):
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Tipo no serializable: {type(value).__name__}")


def create_session(user_id: int, role: str, secret: bytes) -> str:
    expires = int((datetime.utcnow() + timedelta(seconds=SESSION_SECONDS)).timestamp())
    payload = f"{user_id}:{role}:{expires}".encode("utf-8")
    signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return f"{payload.decode('utf-8')}:{signature}"


def verify_session(token: str, secret: bytes) -> dict | None:
    try:
        user_id, role, expires, signature = token.rsplit(":", 3)
        payload = f"{user_id}:{role}:{expires}".encode("utf-8")
        expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected) or int(expires) < int(datetime.utcnow().timestamp()):
            return None
        return {"id": int(user_id), "rol": role}
    except (ValueError, TypeError):
        return None


def create_handler(file_values: dict[str, str], session_secret: bytes):
    class PortalHandler(BaseHTTPRequestHandler):
        server_version = "RADIxECETP"

        def log_message(self, format_string: str, *args) -> None:
            return

        def send_json(self, status: int, payload: dict, headers: dict | None = None) -> None:
            body = json.dumps(payload, ensure_ascii=False, default=serialize_json).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")
            if headers:
                for key, value in headers.items():
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def read_json(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as error:
                raise ValueError("Longitud de solicitud no válida.") from error
            if length <= 0 or length > MAX_REQUEST_BYTES:
                raise ValueError("El cuerpo de la solicitud está vacío o es demasiado grande.")
            try:
                payload = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise ValueError("El cuerpo JSON no es válido.") from error
            if not isinstance(payload, dict):
                raise ValueError("El cuerpo JSON debe ser un objeto.")
            return payload

        def read_session(self) -> dict | None:
            cookies = http.cookies.SimpleCookie()
            try:
                cookies.load(self.headers.get("Cookie", ""))
                token = cookies.get("radixecetp_session")
                if token is None:
                    return None
                return verify_session(token.value, session_secret)
            except http.cookies.CookieError:
                return None

        def require_session(self) -> dict | None:
            user = self.read_session()
            if user is None:
                self.send_json(401, {"error": "Inicia sesión para continuar."})
                return None
            return user

        def verify_origin(self) -> bool:
            origin = self.headers.get("Origin")
            expected = f"http://{HOST}:{self.server.server_port}"
            if origin and origin != expected:
                self.send_json(403, {"error": "Origen de solicitud no permitido."})
                return False
            return True

        def static_file(self, relative: str, content_type: str | None = None) -> None:
            decoded = unquote(relative)
            requested = (ROOT / decoded).resolve()
            try:
                requested.relative_to(ROOT.resolve())
            except ValueError:
                self.send_error(404)
                return
            if not requested.is_file() or requested.name.startswith("."):
                self.send_error(404)
                return
            body = requested.read_bytes()
            guessed_type = content_type or {
                ".css": "text/css",
                ".js": "text/javascript",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
            }.get(requested.suffix.lower(), "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", f"{guessed_type}; charset=utf-8" if guessed_type.startswith(("text/", "application/javascript")) else guessed_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self.static_file("index.html", "text/html")
                return
            for prefix in ("/assets/", "/css/", "/js/"):
                if parsed.path.startswith(prefix):
                    self.static_file(parsed.path.lstrip("/"))
                    return

            if parsed.path == "/api/health":
                try:
                    with open_database(file_values) as connection:
                        with connection.cursor() as cursor:
                            cursor.execute("SELECT DATABASE() AS database_name")
                            database = cursor.fetchone()["database_name"]
                    self.send_json(200, {"status": "ok", "database": database})
                except pymysql.MySQLError as error:
                    self.send_json(503, {"error": f"No se pudo conectar con la base (código {error.args[0]})."})
                return

            if parsed.path == "/api/auth/me":
                session = self.read_session()
                if session is None:
                    self.send_json(200, {"user": None})
                    return
                try:
                    with open_database(file_values) as connection:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                """
                                SELECT id_persona AS id,
                                    CAST(documento_identidad AS CHAR) AS documento,
                                    TRIM(CONCAT_WS(' ', nombre_1, nombre_2,
                                        apellido_1, apellido_2)) AS nombre,
                                    correo_electronico AS correo, telefono, rol, estado
                                FROM persona WHERE id_persona = %s AND estado = 'Activo'
                                LIMIT 1
                                """,
                                (session["id"],),
                            )
                            row = cursor.fetchone()
                    if not row or row["rol"] != session["rol"]:
                        self.send_json(401, {"error": "La sesión ya no está autorizada."})
                        return
                    user = public_user(row)
                    self.send_json(200, {"user": user})
                except pymysql.MySQLError as error:
                    self.send_json(503, {"error": f"No se pudo consultar la cuenta (código {error.args[0]})."})
                return

            if parsed.path == "/api/data":
                session = self.require_session()
                if session is None:
                    return
                try:
                    with open_database(file_values) as connection:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                """
                                SELECT id_persona AS id,
                                    CAST(documento_identidad AS CHAR) AS documento,
                                    TRIM(CONCAT_WS(' ', nombre_1, nombre_2,
                                        apellido_1, apellido_2)) AS nombre,
                                    correo_electronico AS correo, telefono, rol, estado
                                FROM persona
                                WHERE id_persona = %s AND estado = 'Activo'
                                LIMIT 1
                                """,
                                (session["id"],),
                            )
                            row = cursor.fetchone()
                    if not row or row["rol"] != session["rol"]:
                        self.send_json(401, {"error": "La sesión ya no está autorizada."})
                        return
                    data = load_portal_data(public_user(row), file_values)
                    self.send_json(200, data)
                except PermissionError as error:
                    self.send_json(403, {"error": str(error)})
                except pymysql.MySQLError as error:
                    self.send_json(503, {"error": f"No se pudieron cargar los datos (código {error.args[0]})."})
                return

            self.send_json(404, {"error": "Ruta no encontrada."})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/users":
                session = self.require_session()
                if session is None:
                    return
                if not self.verify_origin():
                    return
                if session["rol"] != "Administrador":
                    self.send_json(403, {"error": "Solo el administrador puede crear cuentas."})
                    return
                try:
                    payload = self.read_json()
                except ValueError as error:
                    self.send_json(400, {"error": str(error)})
                    return

                document = payload.get("documento")
                first_name = payload.get("nombre")
                second_name = payload.get("segundoNombre")
                surname = payload.get("apellido")
                second_surname = payload.get("segundoApellido")
                email = payload.get("correo")
                phone = payload.get("telefono")
                gender = payload.get("genero")
                role = payload.get("rol")
                password = payload.get("password")

                if (
                    not isinstance(document, str)
                    or not document.isascii()
                    or not document.isdigit()
                    or len(document) > 19
                    or int(document) <= 0
                    or int(document) > MAX_DOCUMENT_NUMBER
                ):
                    self.send_json(400, {"error": "Ingresa un documento numérico válido."})
                    return
                if (
                    not isinstance(first_name, str)
                    or not first_name.strip()
                    or len(first_name.strip()) > 50
                    or (
                        second_name is not None
                        and (
                            not isinstance(second_name, str)
                            or len(second_name.strip()) > 50
                        )
                    )
                    or not isinstance(surname, str)
                    or not surname.strip()
                    or len(surname.strip()) > 50
                    or (
                        second_surname is not None
                        and (
                            not isinstance(second_surname, str)
                            or len(second_surname.strip()) > 50
                        )
                    )
                ):
                    self.send_json(400, {"error": "Revisa los nombres y apellidos ingresados."})
                    return
                if (
                    email is not None
                    and (
                        not isinstance(email, str)
                        or not email.strip()
                        or len(email.strip()) > 100
                        or "@" not in email
                    )
                ):
                    self.send_json(400, {"error": "Ingresa un correo válido de máximo 100 caracteres."})
                    return
                if (
                    phone is not None
                    and (
                        not isinstance(phone, str)
                        or len(phone.strip()) > 20
                    )
                ):
                    self.send_json(400, {"error": "El teléfono no puede superar 20 caracteres."})
                    return
                if not isinstance(gender, str) or gender not in (
                    "Masculino", "Femenino", "Otro"
                ):
                    self.send_json(400, {"error": "Selecciona una opción de género válida."})
                    return
                if not isinstance(role, str) or role not in ACCOUNT_ROLES:
                    self.send_json(400, {"error": "Selecciona un perfil institucional válido."})
                    return
                if (
                    not isinstance(password, str)
                    or len(password) < 8
                    or len(password) > 200
                ):
                    self.send_json(400, {"error": "La contraseña debe tener entre 8 y 200 caracteres."})
                    return

                try:
                    with open_database(file_values) as connection:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                """
                                SELECT 1 FROM persona
                                WHERE id_persona = %s AND rol = 'Administrador'
                                  AND estado = 'Activo'
                                LIMIT 1
                                """,
                                (session["id"],),
                            )
                            if not cursor.fetchone():
                                self.send_json(403, {"error": "La cuenta administradora ya no está activa."})
                                return
                            cursor.execute(
                                """
                                INSERT INTO persona
                                    (documento_identidad, nombre_1, nombre_2,
                                     apellido_1, apellido_2, correo_electronico,
                                     telefono, genero, rol, `contraseña`, estado)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Activo')
                                """,
                                (
                                    int(document),
                                    first_name.strip(),
                                    second_name.strip() or None if second_name else None,
                                    surname.strip(),
                                    second_surname.strip() or None if second_surname else None,
                                    email.strip() if email else None,
                                    phone.strip() if phone else None,
                                    gender,
                                    role,
                                    hash_password(password),
                                ),
                            )
                            person_id = cursor.lastrowid
                            if role == "Estudiante":
                                cursor.execute(
                                    "INSERT INTO estudiante (id_persona) VALUES (%s)",
                                    (person_id,),
                                )
                        connection.commit()
                except pymysql.err.IntegrityError as error:
                    if error.args and error.args[0] == 1062:
                        self.send_json(409, {"error": "Ya existe una cuenta con ese documento."})
                    else:
                        self.send_json(503, {"error": f"No se pudo crear la cuenta (código {error.args[0] if error.args else 'desconocido'})."})
                    return
                except pymysql.MySQLError as error:
                    self.send_json(503, {"error": f"No se pudo crear la cuenta (código {error.args[0] if error.args else 'desconocido'})."})
                    return

                self.send_json(
                    201,
                    {"message": f"Cuenta de {role.lower()} creada correctamente."},
                )
                return

            if parsed.path == "/api/auth/login":
                if not self.verify_origin():
                    return
                try:
                    payload = self.read_json()
                except ValueError as error:
                    self.send_json(400, {"error": str(error)})
                    return
                documento = str(payload.get("documento") or "").strip()
                password = payload.get("password")
                if not documento or not isinstance(password, str) or len(password) > 200:
                    self.send_json(400, {"error": "Ingresa un documento y una contraseña válidos."})
                    return
                try:
                    with open_database(file_values) as connection:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                """
                                SELECT id_persona AS id,
                                    CAST(documento_identidad AS CHAR) AS documento,
                                    nombre_1, nombre_2, apellido_1, apellido_2,
                                    correo_electronico AS correo, telefono, rol, estado,
                                    `contraseña` AS password_value
                                FROM persona WHERE documento_identidad = %s LIMIT 1
                                """,
                                (documento,),
                            )
                            row = cursor.fetchone()
                except pymysql.MySQLError as error:
                    self.send_json(503, {"error": f"No se pudo consultar el acceso (código {error.args[0]})."})
                    return

                if not row or row["rol"] not in ALLOWED_ROLES:
                    self.send_json(401, {"error": "El documento o la contraseña no coinciden."})
                    return
                stored_password = row["password_value"]
                if not isinstance(stored_password, str) or not verify_password(stored_password, password):
                    self.send_json(401, {"error": "El documento o la contraseña no coinciden."})
                    return
                if row["estado"] != "Activo":
                    self.send_json(401, {"error": "Esta cuenta está inactiva."})
                    return

                user = public_user({
                    **row,
                    "nombre": " ".join(
                        part for part in (
                            row["nombre_1"], row["nombre_2"],
                            row["apellido_1"], row["apellido_2"],
                        ) if part
                    ),
                })
                token = create_session(user["id"], user["rol"], session_secret)
                self.send_json(
                    200,
                    {"user": user},
                    {"Set-Cookie": f"radixecetp_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"},
                )
                return

            if parsed.path == "/api/auth/logout":
                if not self.verify_origin():
                    return
                self.send_json(
                    200,
                    {"status": "ok"},
                    {"Set-Cookie": "radixecetp_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"},
                )
                return

            if parsed.path == "/api/annotations":
                session = self.require_session()
                if session is None:
                    return
                if session["rol"] != "Docente":
                    self.send_json(403, {"error": "Solo un docente puede registrar anotaciones."})
                    return
                if not self.verify_origin():
                    return
                try:
                    payload = self.read_json()
                    student_id = int(payload.get("studentId"))
                    annotation_date = datetime.strptime(payload.get("fecha", ""), "%Y-%m-%dT%H:%M")
                    annotation_type = payload.get("tipo")
                    description = payload.get("descripcion")
                    if annotation_type not in ANNOTATION_TYPES:
                        raise ValueError
                    if not isinstance(description, str) or not description.strip() or len(description.strip()) > 1000:
                        raise ValueError
                except (ValueError, TypeError):
                    self.send_json(400, {"error": "Revisa los datos de la anotación."})
                    return
                try:
                    with open_database(file_values) as connection:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                """
                                SELECT e.id_estudiante
                                FROM estudiante e
                                JOIN asignacion a ON a.id_grupo = COALESCE(
                                    (SELECT m.id_grupo FROM matricula m
                                     WHERE m.id_persona = e.id_persona
                                     ORDER BY m.anio_lectivo DESC LIMIT 1),
                                    e.id_grupo
                                )
                                WHERE e.id_persona = %s AND a.id_persona = %s
                                LIMIT 1
                                """,
                                (student_id, session["id"]),
                            )
                            student = cursor.fetchone()
                            if not student:
                                self.send_json(403, {"error": "No tienes asignado el grupo de este estudiante."})
                                return
                            cursor.execute(
                                """
                                INSERT INTO anotaciones
                                    (id_estudiante, id_docente, fecha_hora,
                                     tipo_falta, descripcion_anotacion, estado_apelacion)
                                VALUES (%s, %s, %s, %s, %s, 'Sin Apelación')
                                """,
                                (
                                    student["id_estudiante"], session["id"], annotation_date,
                                    annotation_type, description.strip(),
                                ),
                            )
                        connection.commit()
                    self.send_json(201, {"message": "Anotación guardada en Aiven."})
                except pymysql.MySQLError as error:
                    self.send_json(503, {"error": f"No se pudo guardar la anotación (código {error.args[0]})."})
                return

            if parsed.path == "/api/grades":
                self.send_json(
                    409,
                    {"error": "La tabla notas no relaciona sus filas con estudiantes, docentes y materias; no se pueden guardar calificaciones sin esas relaciones."},
                )
                return

            self.send_json(404, {"error": "Ruta no encontrada."})

        def do_PATCH(self) -> None:
            parsed = urlparse(self.path)
            session = self.require_session()
            if session is None:
                return
            if not self.verify_origin():
                return

            try:
                payload = self.read_json()
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
                return

            if parsed.path == "/api/profile":
                try:
                    name = payload.get("nombre")
                    email = payload.get("correo") or None
                    phone = payload.get("telefono") or None
                    if (
                        not isinstance(name, str) or len(name.strip()) < 2 or len(name.strip()) > 200
                        or (email is not None and (not isinstance(email, str) or len(email) > 100 or "@" not in email))
                        or (phone is not None and (not isinstance(phone, str) or len(phone) > 20))
                    ):
                        raise ValueError
                    parts = name.strip().split()
                    first_name = parts[0]
                    second_name = parts[1] if len(parts) >= 4 else None
                    first_surname = parts[2] if len(parts) >= 4 else (parts[1] if len(parts) >= 2 else parts[0])
                    second_surname = parts[3] if len(parts) >= 4 else (parts[2] if len(parts) >= 3 else None)
                except ValueError:
                    self.send_json(400, {"error": "Revisa el nombre, correo y teléfono."})
                    return
                try:
                    with open_database(file_values) as connection:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                """
                                UPDATE persona
                                SET nombre_1 = %s, nombre_2 = %s,
                                    apellido_1 = %s, apellido_2 = %s,
                                    correo_electronico = %s, telefono = %s
                                WHERE id_persona = %s AND estado = 'Activo'
                                """,
                                (
                                    first_name, second_name, first_surname, second_surname,
                                    email, phone, session["id"],
                                ),
                            )
                        connection.commit()
                    self.send_json(200, {"message": "Perfil actualizado en Aiven."})
                except pymysql.MySQLError as error:
                    self.send_json(503, {"error": f"No se pudo guardar el perfil (código {error.args[0]})."})
                return

            pieces = parsed.path.strip("/").split("/")
            if len(pieces) == 4 and pieces[:2] == ["api", "annotations"] and pieces[3] == "appeal":
                if session["rol"] != "Estudiante":
                    self.send_json(403, {"error": "Solo el estudiante puede enviar esta apelación."})
                    return
                version = payload.get("version")
                if not isinstance(version, str) or not version.strip() or len(version.strip()) > 1500:
                    self.send_json(400, {"error": "La apelación debe tener entre 1 y 1500 caracteres."})
                    return
                try:
                    annotation_id = int(pieces[2])
                    with open_database(file_values) as connection:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                """
                                UPDATE anotaciones a
                                JOIN estudiante e ON e.id_estudiante = a.id_estudiante
                                SET a.version_estudiante = %s, a.estado_apelacion = 'En Revisión'
                                WHERE a.id_anotacion = %s AND e.id_persona = %s
                                  AND a.estado_apelacion NOT IN ('Aprobada', 'Rechazada')
                                """,
                                (version.strip(), annotation_id, session["id"]),
                            )
                            changed = cursor.rowcount
                        connection.commit()
                    if not changed:
                        self.send_json(404, {"error": "No se encontró una anotación apelable."})
                    else:
                        self.send_json(200, {"message": "Apelación guardada en Aiven."})
                except (ValueError, pymysql.MySQLError) as error:
                    code = error.args[0] if isinstance(error, pymysql.MySQLError) and error.args else "no válido"
                    self.send_json(400 if not isinstance(error, pymysql.MySQLError) else 503, {"error": f"No se pudo guardar la apelación ({code})."})
                return

            if len(pieces) == 4 and pieces[:2] == ["api", "annotations"] and pieces[3] == "review":
                if session["rol"] not in STAFF_ROLES:
                    self.send_json(403, {"error": "No tienes permiso para revisar apelaciones."})
                    return
                status = payload.get("estado")
                if status not in APPEAL_STATES:
                    self.send_json(400, {"error": "Estado de apelación no válido."})
                    return
                try:
                    annotation_id = int(pieces[2])
                except ValueError:
                    self.send_json(400, {"error": "Identificador de anotación no válido."})
                    return
                try:
                    with open_database(file_values) as connection:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                """
                                UPDATE anotaciones
                                SET estado_apelacion = %s
                                WHERE id_anotacion = %s
                                  AND version_estudiante IS NOT NULL
                                  AND version_estudiante <> ''
                                """,
                                (status, annotation_id),
                            )
                            changed = cursor.rowcount
                        connection.commit()
                    if not changed:
                        self.send_json(404, {"error": "No se encontró una apelación para revisar."})
                    else:
                        self.send_json(200, {"message": "Estado de apelación guardado en Aiven."})
                except pymysql.MySQLError as error:
                    self.send_json(503, {"error": f"No se pudo actualizar la apelación (código {error.args[0]})."})
                return

            self.send_json(404, {"error": "Ruta no encontrada."})

    return PortalHandler


def main() -> int:
    file_values = read_env_file(ENV_FILE)
    required = ("DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME")
    missing = [name for name in required if not get_setting(name, file_values)]
    if missing:
        print("Faltan estas variables en .env: " + ", ".join(missing))
        return 1
    try:
        port = int(get_setting("DB_PORT", file_values))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        print("DB_PORT debe ser un puerto entre 1 y 65535.")
        return 1

    print("\n  RADIxECETP  ·  Portal académico\n", flush=True)
    print("  [1/3] Conectando con Aiven MySQL por TLS…", flush=True)
    try:
        with open_database(file_values) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT DATABASE() AS database_name")
                database_name = cursor.fetchone()["database_name"]
                cursor.execute("SELECT COUNT(*) AS people FROM persona")
                people_count = cursor.fetchone()["people"]
    except pymysql.MySQLError as error:
        code = error.args[0] if error.args else "desconocido"
        print(f"  No se pudo conectar con Aiven (código {code}).", flush=True)
        return 1
    except (OSError, ssl.SSLError) as error:
        print(f"  No se pudo establecer TLS ({type(error).__name__}).", flush=True)
        return 1

    session_secret = secrets.token_bytes(32)
    try:
        server = ThreadingHTTPServer(
            (HOST, PORT),
            create_handler(file_values, session_secret),
        )
    except OSError as error:
        print(f"  No se pudo iniciar el servidor local en el puerto {PORT}: {error}", flush=True)
        return 1

    url = f"http://{HOST}:{PORT}/"
    print(f"  [2/3] Conectado a {database_name}; {people_count} personas registradas.", flush=True)
    print("  [3/3] Portal listo. Abre este enlace:\n", flush=True)
    print(f"    {url}\n", flush=True)
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Cerrando el portal…", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
