'use strict';

require('dotenv').config();

const path = require('path');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const { createDatabasePool } = require('./db');

const app = express();
const port = Number(process.env.PORT || 3000);
const sessionSecret = process.env.SESSION_SECRET;
const isProduction = process.env.NODE_ENV === 'production';
const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: 'strict',
  path: '/',
  maxAge: 8 * 60 * 60 * 1000
};
const pool = createDatabasePool();

if (!sessionSecret || sessionSecret.length < 32) {
  throw new Error('SESSION_SECRET debe tener al menos 32 caracteres.');
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());
app.use('/assets', express.static(path.join(__dirname, 'assets'), { dotfiles: 'deny' }));
app.use('/css', express.static(path.join(__dirname, 'css'), { dotfiles: 'deny' }));
app.use('/js', express.static(path.join(__dirname, 'js'), { dotfiles: 'deny' }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/api/health', async (req, res, next) => {
  try {
    await pool.query('SELECT 1');
    await pool.query(
      'SELECT `id_persona`, `documento_identidad`, `contraseña` FROM `persona` LIMIT 0'
    );
    await pool.query(
      'SELECT `id_nota`, `calficacion`, `autoevaluacion`, `coevalucion`, `total`, `estado`, `descripcion` FROM `notas` LIMIT 0'
    );
    await pool.query(
      'SELECT `id_estudiante`, `id_persona`, `id_grupo` FROM `estudiante` LIMIT 0'
    );
    await pool.query(
      'SELECT `id_persona`, `id_materia`, `id_grupo` FROM `asignacion` LIMIT 0'
    );
    await pool.query(
      'SELECT `id_materia`, `nombre_materia`, `intensidad_horaria` FROM `materia` LIMIT 0'
    );
    await pool.query(
      'SELECT `id_grupo`, `nombre_grupo`, `grado` FROM `grupo` LIMIT 0'
    );
    await pool.query(
      'SELECT `id_persona`, `id_grupo`, `anio_lectivo` FROM `matricula` LIMIT 0'
    );
    await pool.query(
      'SELECT `id_anotacion`, `id_estudiante`, `id_docente`, `tipo_falta`, `descripcion_anotacion`, `version_estudiante`, `estado_apelacion` FROM `anotaciones` LIMIT 0'
    );
    res.json({ status: 'ok', database: 'connected' });
  } catch (error) {
    next(error);
  }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const documento = String(req.body?.documento || '').trim();
    const password = req.body?.password;

    if (!documento || typeof password !== 'string' || password.length > 200) {
      return res.status(400).json({ error: 'Ingresa un documento y una contraseña válidos.' });
    }

    const [rows] = await pool.execute(
      'SELECT `id_persona`, `documento_identidad`, `nombre_1`, `nombre_2`, `apellido_1`, `apellido_2`, `correo_electronico`, `telefono`, `rol`, `estado`, `contraseña` FROM `persona` WHERE `documento_identidad` = ? LIMIT 1',
      [documento]
    );
    const user = rows[0];
    if (user && !['Administrador', 'Docente', 'Estudiante'].includes(user.rol)) {
      return res.status(403).json({ error: 'Este perfil aún no está habilitado para acceder al portal.' });
    }
    const passwordMatches = user && /^\$2[aby]\$\d{2}\$/.test(user.contraseña)
      ? await bcrypt.compare(password, user.contraseña)
      : false;

    if (!passwordMatches || user.estado !== 'Activo') {
      return res.status(401).json({ error: 'El documento o la contraseña no coinciden.' });
    }

    const token = jwt.sign(
      { sub: String(user.id_persona), role: user.rol },
      sessionSecret,
      { expiresIn: '8h', issuer: 'radixecetp' }
    );
    const nombre = [user.nombre_1, user.nombre_2, user.apellido_1, user.apellido_2]
      .filter(Boolean)
      .join(' ');

    res.cookie('radixecetp_session', token, cookieOptions);
    res.json({
      user: {
        id: user.id_persona,
        documento: String(user.documento_identidad),
        nombre,
        rol: user.rol,
        correo: user.correo_electronico,
        telefono: user.telefono
      }
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/me', async (req, res, next) => {
  const token = req.cookies.radixecetp_session;
  if (!token) {
    return res.status(401).json({ error: 'Sesión no autenticada.' });
  }

  let claims;
  try {
    claims = jwt.verify(token, sessionSecret, { issuer: 'radixecetp' });
  } catch {
    return res.status(401).json({ error: 'La sesión expiró o no es válida.' });
  }

  try {
    const [rows] = await pool.execute(
      'SELECT `id_persona`, `documento_identidad`, `nombre_1`, `nombre_2`, `apellido_1`, `apellido_2`, `correo_electronico`, `telefono`, `rol` FROM `persona` WHERE `id_persona` = ? AND `estado` = ? LIMIT 1',
      [claims.sub, 'Activo']
    );
    const user = rows[0];
    if (!user || user.rol !== claims.role) {
      const { maxAge, ...clearOptions } = cookieOptions;
      res.clearCookie('radixecetp_session', clearOptions);
      return res.status(401).json({ error: 'La sesión no está autorizada.' });
    }

    res.json({
      user: {
        id: user.id_persona,
        documento: String(user.documento_identidad),
        nombre: [user.nombre_1, user.nombre_2, user.apellido_1, user.apellido_2]
          .filter(Boolean)
          .join(' '),
        rol: user.rol,
        correo: user.correo_electronico,
        telefono: user.telefono
      }
    });
  } catch (error) {
    next(error);
  }
});

function requireSession(req, res, next) {
  try {
    const token = req.cookies.radixecetp_session;
    if (!token) return res.status(401).json({ error: 'Inicia sesión para continuar.' });
    req.session = jwt.verify(token, sessionSecret, { issuer: 'radixecetp' });
    next();
  } catch {
    res.status(401).json({ error: 'La sesión expiró o no es válida.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.session.role)) {
      return res.status(403).json({ error: 'No tienes permiso para esta operación.' });
    }
    next();
  };
}

function verifySameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && origin !== `${req.protocol}://${req.get('host')}`) {
    return res.status(403).json({ error: 'Origen de solicitud no permitido.' });
  }
  next();
}

const staffRoles = ['Administrador', 'Coordinador', 'Rector'];

app.get('/api/data', requireSession, async (req, res, next) => {
  try {
    const userId = Number(req.session.sub);
    const role = req.session.role;
    const isStaff = staffRoles.includes(role);
    const isTeacher = role === 'Docente';
    const isStudent = role === 'Estudiante';
    if (!isStaff && !isTeacher && !isStudent) {
      return res.status(403).json({ error: 'Este perfil no tiene acceso al portal.' });
    }

    const userCondition = isStaff
      ? ''
      : isStudent
        ? 'WHERE p.id_persona = ?'
        : "WHERE p.rol IN ('Estudiante', 'Docente')";
    const userParams = isStudent ? [userId] : [];
    const userDetails = isStaff
      ? 'CAST(p.documento_identidad AS CHAR) AS documento, p.correo_electronico AS correo, p.telefono, e.nombre_completo_acudiente AS acudiente, e.parentezco_acudiente AS parentesco'
      : isStudent
        ? 'NULL AS documento, p.correo_electronico AS correo, p.telefono, e.nombre_completo_acudiente AS acudiente, e.parentezco_acudiente AS parentesco'
        : 'NULL AS documento, NULL AS correo, NULL AS telefono, NULL AS acudiente, NULL AS parentesco';
    const [people] = await pool.execute(
      `SELECT p.id_persona AS id,
        TRIM(CONCAT_WS(' ', p.nombre_1, p.nombre_2, p.apellido_1, p.apellido_2)) AS nombre,
        ${userDetails}, p.rol, p.estado,
        e.id_estudiante, COALESCE(m.id_grupo, e.id_grupo) AS id_grupo,
        g.nombre_grupo AS grupo
       FROM persona p
       LEFT JOIN estudiante e ON e.id_persona = p.id_persona
       LEFT JOIN matricula m ON m.id_persona = p.id_persona
         AND m.anio_lectivo = (SELECT MAX(m2.anio_lectivo) FROM matricula m2 WHERE m2.id_persona = p.id_persona)
       LEFT JOIN grupo g ON g.id_grupo = COALESCE(m.id_grupo, e.id_grupo)
       ${userCondition}
       ORDER BY p.id_persona`,
      userParams
    );

    const assignmentsCondition = isTeacher
      ? 'WHERE a.id_persona = ?'
      : isStudent
        ? 'WHERE a.id_grupo = COALESCE((SELECT m.id_grupo FROM matricula m WHERE m.id_persona = ? ORDER BY m.anio_lectivo DESC LIMIT 1), (SELECT e.id_grupo FROM estudiante e WHERE e.id_persona = ? LIMIT 1))'
        : '';
    const assignmentParams = isTeacher ? [userId] : isStudent ? [userId, userId] : [];
    const [assignmentRows] = await pool.execute(
      `SELECT a.\`id_asignación\` AS id, a.id_persona AS teacherId,
        a.id_materia AS subjectId, a.id_grupo AS groupId,
        ma.nombre_materia AS subjectName, ma.intensidad_horaria AS intensidad,
        g.nombre_grupo AS groupName, g.grado
       FROM asignacion a
       JOIN materia ma ON ma.id_materia = a.id_materia
       JOIN grupo g ON g.id_grupo = a.id_grupo
       ${assignmentsCondition}
       ORDER BY g.grado, ma.nombre_materia`,
      assignmentParams
    );

    const annotationCondition = isTeacher
      ? 'WHERE a.id_docente = ?'
      : isStudent
        ? 'WHERE e.id_persona = ?'
        : '';
    const annotationParams = isTeacher || isStudent ? [userId] : [];
    const [annotationRows] = await pool.execute(
      `SELECT a.id_anotacion AS id, e.id_persona AS studentId,
        a.id_docente AS teacherId,
        DATE_FORMAT(a.fecha_hora, '%Y-%m-%dT%H:%i') AS fecha,
        a.tipo_falta AS tipo, a.descripcion_anotacion AS descripcion,
        a.version_estudiante AS version, a.estado_apelacion AS estado
       FROM anotaciones a
       JOIN estudiante e ON e.id_estudiante = a.id_estudiante
       ${annotationCondition}
       ORDER BY a.fecha_hora DESC`,
      annotationParams
    );

    const groups = [...new Map(assignmentRows.map((row) => [
      row.groupId,
      { id: row.groupId, nombre: row.groupName, grado: row.grado }
    ])).values()];
    const subjects = [...new Map(assignmentRows.map((row) => [
      row.subjectId,
      {
        id: row.subjectId,
        nombre: row.subjectName,
        intensidad: row.intensidad,
        docenteId: row.teacherId,
        grupoId: row.groupId
      }
    ])).values()];
    const assignments = assignmentRows.map(({ id, teacherId, subjectId, groupId }) => ({
      id, teacherId, subjectId, groupId
    }));

    res.set('Cache-Control', 'no-store');
    res.json({
      users: people.map(({ id_estudiante, id_grupo, ...person }) => ({
        ...person,
        grupoId: id_grupo
      })),
      groups,
      subjects,
      assignments,
      grades: [],
      annotations: annotationRows
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/grades', requireSession, requireRole('Docente'), verifySameOrigin, async (req, res, next) => {
  try {
    return res.status(409).json({
      error: 'La tabla notas de Aiven no relaciona las calificaciones con estudiante, docente y materia. Solicita al administrador de la base completar ese esquema antes de registrar notas.'
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/annotations', requireSession, requireRole('Docente'), verifySameOrigin, async (req, res, next) => {
  try {
    const { studentId, fecha, tipo, descripcion } = req.body || {};
    const allowedTypes = ['Tipo 1 - Leve', 'Tipo 2 - Grave', 'Tipo 3 - Gravísima'];
    if (!Number.isInteger(Number(studentId)) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(fecha || '')
      || !allowedTypes.includes(tipo) || typeof descripcion !== 'string'
      || !descripcion.trim() || descripcion.trim().length > 1000) {
      return res.status(400).json({ error: 'Revisa los datos de la anotación.' });
    }

    const [assignments] = await pool.execute(
      `SELECT 1 FROM estudiante e
       JOIN asignacion a ON a.id_grupo = COALESCE(
         (SELECT m.id_grupo FROM matricula m WHERE m.id_persona = e.id_persona
          ORDER BY m.anio_lectivo DESC LIMIT 1), e.id_grupo)
       WHERE e.id_persona = ? AND a.id_persona = ? LIMIT 1`,
      [studentId, req.session.sub]
    );
    if (!assignments.length) return res.status(403).json({ error: 'No tienes asignado el grupo de este estudiante.' });

    await pool.execute(
      'INSERT INTO anotaciones (`id_estudiante`, `id_docente`, `fecha_hora`, `tipo_falta`, `descripcion_anotacion`, `estado_apelacion`) SELECT e.id_estudiante, ?, ?, ?, ?, ? FROM estudiante e WHERE e.id_persona = ?',
      [req.session.sub, fecha.replace('T', ' '), tipo, descripcion.trim(), 'Sin Apelación', studentId]
    );
    res.status(201).json({ message: 'Anotación guardada.' });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/annotations/:id/appeal', requireSession, requireRole('Estudiante'), verifySameOrigin, async (req, res, next) => {
  try {
    const version = req.body?.version;
    if (typeof version !== 'string' || !version.trim() || version.trim().length > 1500) {
      return res.status(400).json({ error: 'La apelación debe tener entre 1 y 1500 caracteres.' });
    }
    const [result] = await pool.execute(
      `UPDATE anotaciones a
       JOIN estudiante e ON e.id_estudiante = a.id_estudiante
       SET a.version_estudiante = ?, a.estado_apelacion = ?
       WHERE a.id_anotacion = ? AND e.id_persona = ?
         AND a.estado_apelacion NOT IN ('Aprobada', 'Rechazada')`,
      [version.trim(), 'En Revisión', req.params.id, req.session.sub]
    );
    if (!result.affectedRows) return res.status(404).json({ error: 'No se encontró una anotación apelable.' });
    res.json({ message: 'Apelación guardada.' });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/annotations/:id/review', requireSession, requireRole(...staffRoles), verifySameOrigin, async (req, res, next) => {
  try {
    const status = req.body?.estado;
    if (!['Aprobada', 'Rechazada', 'En Revisión'].includes(status)) {
      return res.status(400).json({ error: 'Estado de apelación no válido.' });
    }
    const [result] = await pool.execute(
      "UPDATE anotaciones SET estado_apelacion = ? WHERE id_anotacion = ? AND version_estudiante IS NOT NULL AND version_estudiante <> ''",
      [status, req.params.id]
    );
    if (!result.affectedRows) return res.status(404).json({ error: 'No se encontró una apelación para revisar.' });
    res.json({ message: 'Estado de apelación actualizado.' });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/profile', requireSession, verifySameOrigin, async (req, res, next) => {
  try {
    const { nombre, correo, telefono } = req.body || {};
    if (typeof nombre !== 'string' || nombre.trim().length < 2 || nombre.trim().length > 200
      || (correo && (typeof correo !== 'string' || correo.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)))
      || (telefono && (typeof telefono !== 'string' || telefono.length > 20))) {
      return res.status(400).json({ error: 'Revisa el nombre, correo y teléfono.' });
    }

    const parts = nombre.trim().split(/\s+/);
    const [result] = await pool.execute(
      `UPDATE persona SET nombre_1 = ?, nombre_2 = NULL, apellido_1 = ?, apellido_2 = NULL,
       correo_electronico = ?, telefono = ? WHERE id_persona = ? AND estado = 'Activo'`,
      [parts[0], parts.slice(1).join(' ') || parts[0], correo || null, telefono || null, req.session.sub]
    );
    if (!result.affectedRows) {
      const [users] = await pool.execute(
        'SELECT 1 FROM persona WHERE id_persona = ? AND estado = ? LIMIT 1',
        [req.session.sub, 'Activo']
      );
      if (!users.length) return res.status(404).json({ error: 'No se encontró el perfil.' });
    }
    res.json({ message: 'Perfil actualizado.' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/logout', verifySameOrigin, (req, res) => {
  const { maxAge, ...clearOptions } = cookieOptions;
  res.clearCookie('radixecetp_session', clearOptions);
  res.status(204).end();
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Ruta API no encontrada.' }));
app.use((req, res) => res.status(404).send('No encontrado.'));

app.use((error, req, res, next) => {
  console.error('Error en la API:', error.message);
  if (res.headersSent) return next(error);
  res.status(503).json({ error: 'El servicio no pudo completar la solicitud.' });
});

const server = app.listen(port, () => {
  console.log(`RADIxECETP API escuchando en el puerto ${port}.`);
});

async function shutdown() {
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
