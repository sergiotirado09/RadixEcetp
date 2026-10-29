'use strict';

const apiRequest = async (url, options = {}) => {
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers
    }
  });
  if (response.status === 204) return null;

  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(result.error || `Error del servidor (${response.status}).`);
  }
  return result;
};

const showApiError = (element, error) => {
  if (!element) return;
  const message = error.message || 'No se pudo completar la solicitud.';
  if (element instanceof HTMLFormElement) {
    let errorMessage = element.querySelector('[data-api-error]');
    if (!errorMessage) {
      errorMessage = document.createElement('p');
      errorMessage.className = 'msg';
      errorMessage.dataset.apiError = 'true';
      errorMessage.setAttribute('role', 'alert');
      element.append(errorMessage);
    }
    errorMessage.textContent = message;
    return;
  }
  element.textContent = message;
};

const refreshPortalData = async () => {
  db = await apiRequest('/api/data');
  renderView();
};

const completeLogin = async (user) => {
  const portalData = await apiRequest('/api/data');
  currentUser = user;
  db = portalData;
  $('publicPage').classList.add('hidden');
  $('appPage').classList.remove('hidden');
  $('headerName').textContent = `${user.nombre} · ${user.rol}`;
  configureNavigation();
  renderView();
  window.scrollTo(0, 0);
};

const loginForm = $('loginForm');

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  event.stopImmediatePropagation();
  const message = $('loginMessage');
  message.textContent = 'Conectando…';

  try {
    const result = await apiRequest('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        documento: $('loginUser').value.trim(),
        password: $('loginPassword').value
      })
    });
    await completeLogin(result.user);
    message.textContent = '';
  } catch (error) {
    message.textContent = error.message;
  }
}, true);

const logoutButtons = [$('logoutTop'), $('logoutSide')];
logoutButtons.forEach((button) => {
  button.addEventListener('click', async (event) => {
    event.preventDefault();
    event.stopImmediatePropagation();
    let logoutFailed = false;
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } catch {
      logoutFailed = true;
    }
    currentUser = null;
    db = loadDB();
    $('appPage').classList.add('hidden');
    $('publicPage').classList.remove('hidden');
    $('loginPassword').value = '';
    $('loginMessage').textContent = logoutFailed
      ? 'Se cerró esta sesión, pero el servidor no pudo confirmar el cierre. Cierra el navegador en un dispositivo compartido.'
      : '';
    window.scrollTo(0, 0);
  }, true);
});

attachEvents = function attachApiEvents() {
  if (currentView === 'inicio' && isAdmin()) drawDashboardCharts();

  if (currentView === 'calificaciones' && isTeacher()) {
    $('gradeForm').onsubmit = async (event) => {
      event.preventDefault();
      const scores = ['gradeValue', 'gradeSelf', 'gradeCo'].map((id) => Number($(id).value || 0));
      const message = $('gradeMsg');
      if (scores.some((score) => score < 0 || score > 5)) {
        message.textContent = 'Las calificaciones deben estar entre 0 y 5.';
        return;
      }

      try {
        await apiRequest('/api/grades', {
          method: 'POST',
          body: JSON.stringify({
            studentId: Number($('gradeStudent').value),
            subjectId: Number($('gradeSubject').value),
            calificacion: scores[0],
            autoevaluacion: scores[1],
            coevaluacion: scores[2],
            descripcion: $('gradeDescription').value.trim(),
            fecha: $('gradeDate').value
          })
        });
        await refreshPortalData();
      } catch (error) {
        showApiError(message, error);
      }
    };
  }

  if (currentView === 'anotaciones') {
    const annotationForm = $('annotationForm');
    if (annotationForm) {
      annotationForm.onsubmit = async (event) => {
        event.preventDefault();
        const message = $('annotationMsg');
        try {
          await apiRequest('/api/annotations', {
            method: 'POST',
            body: JSON.stringify({
              studentId: Number($('annotationStudent').value),
              fecha: $('annotationDate').value,
              tipo: $('annotationType').value,
              descripcion: $('annotationDescription').value.trim()
            })
          });
          await refreshPortalData();
        } catch (error) {
          showApiError(message, error);
        }
      };
    }

    document.querySelectorAll('.appealForm').forEach((form) => {
      form.onsubmit = async (event) => {
        event.preventDefault();
        const button = form.querySelector('button');
        button.disabled = true;
        try {
          await apiRequest(`/api/annotations/${encodeURIComponent(form.dataset.appeal)}/appeal`, {
            method: 'PATCH',
            body: JSON.stringify({ version: form.querySelector('textarea').value.trim() })
          });
          await refreshPortalData();
        } catch (error) {
          button.disabled = false;
          showApiError(form, error);
        }
      };
    });

    document.querySelectorAll('[data-review]').forEach((button) => {
      button.onclick = async () => {
        button.disabled = true;
        try {
          await apiRequest(`/api/annotations/${encodeURIComponent(button.dataset.review)}/review`, {
            method: 'PATCH',
            body: JSON.stringify({ estado: button.dataset.status })
          });
          await refreshPortalData();
        } catch (error) {
          button.disabled = false;
          window.alert(error.message);
        }
      };
    });
  }

  if (currentView === 'usuarios') {
    const createUserForm = $('createUserForm');
    if (createUserForm && isAdmin()) {
      createUserForm.onsubmit = async (event) => {
        event.preventDefault();
        const message = $('createUserMsg');
        const password = $('newUserPassword').value;
        if (password !== $('newUserPasswordConfirm').value) {
          message.textContent = 'Las contraseñas no coinciden.';
          return;
        }
        const button = createUserForm.querySelector('button[type="submit"]');
        button.disabled = true;
        message.textContent = 'Creando cuenta…';

        try {
          const result = await apiRequest('/api/users', {
            method: 'POST',
            body: JSON.stringify({
              documento: $('newUserDocument').value.trim(),
              nombre: $('newUserFirstName').value.trim(),
              segundoNombre: $('newUserSecondName').value.trim(),
              apellido: $('newUserSurname').value.trim(),
              segundoApellido: $('newUserSecondSurname').value.trim(),
              correo: $('newUserEmail').value.trim(),
              telefono: $('newUserPhone').value.trim(),
              genero: $('newUserGender').value,
              rol: $('newUserRole').value,
              password
            })
          });
          createUserForm.reset();
          await refreshPortalData();
          $('createUserMsg').textContent = result.message;
        } catch (error) {
          button.disabled = false;
          showApiError(message, error);
        }
      };
    }

    document.querySelectorAll('[data-dbtable]').forEach((button) => {
      button.onclick = () => {
        dbTable = button.dataset.dbtable;
        renderView();
      };
    });
    $('dbSearch').oninput = refreshDatabase;
    $('exportTable').onclick = exportCurrentTable;
    const downloadBackupButton = $('downloadBackup');
    if (downloadBackupButton) downloadBackupButton.disabled = true;
    const resetButton = $('resetDB');
    if (resetButton) resetButton.disabled = true;
    refreshDatabase();
  }

  if (currentView === 'perfil') {
    $('profileForm').onsubmit = async (event) => {
      event.preventDefault();
      const message = $('profileMsg');
      try {
        await apiRequest('/api/profile', {
          method: 'PATCH',
          body: JSON.stringify({
            nombre: $('profileName').value.trim(),
            correo: $('profileEmail').value.trim(),
            telefono: $('profilePhone').value.trim()
          })
        });
        const session = await apiRequest('/api/auth/me');
        currentUser = session.user;
        $('headerName').textContent = `${currentUser.nombre} · ${currentUser.rol}`;
        await refreshPortalData();
      } catch (error) {
        showApiError(message, error);
      }
    };
  }
};

const previousRenderHome = renderHome;
renderHome = function renderConnectedHome() {
  return previousRenderHome().replace(
    'Esta es una base de datos interna de demostración guardada en el navegador. No consulta ni modifica el archivo SQL adjunto.',
    'La información de esta vista se carga desde la base de datos institucional.'
  );
};

renderDatabase = function renderConnectedDatabase() {
  const names = {
    users: 'Personas / usuarios',
    groups: 'Grupos',
    subjects: 'Materias',
    grades: 'Notas',
    annotations: 'Anotaciones y apelaciones',
    assignments: 'Asignaciones'
  };
  const createAccountForm = isAdmin()
    ? `<section class="panel"><h2>Crear cuenta institucional</h2>` +
      `<p class="small-note">Solo el administrador puede crear cuentas. Las cuentas nuevas tendrán acceso inmediato con la contraseña asignada.</p>` +
      `<form id="createUserForm"><div class="form-grid">` +
      `<div><label for="newUserDocument">Documento *</label><input id="newUserDocument" inputmode="numeric" pattern="[0-9]+" maxlength="19" required></div>` +
      `<div><label for="newUserRole">Perfil *</label><select id="newUserRole" required>` +
      `<option value="Estudiante">Estudiante</option><option value="Docente">Docente</option><option value="Coordinador">Coordinador</option><option value="Rector">Rector</option><option value="Administrador">Administrador</option></select></div>` +
      `<div><label for="newUserFirstName">Primer nombre *</label><input id="newUserFirstName" maxlength="50" required></div>` +
      `<div><label for="newUserSecondName">Segundo nombre</label><input id="newUserSecondName" maxlength="50"></div>` +
      `<div><label for="newUserSurname">Primer apellido *</label><input id="newUserSurname" maxlength="50" required></div>` +
      `<div><label for="newUserSecondSurname">Segundo apellido</label><input id="newUserSecondSurname" maxlength="50"></div>` +
      `<div><label for="newUserEmail">Correo</label><input id="newUserEmail" type="email" maxlength="100"></div>` +
      `<div><label for="newUserPhone">Teléfono</label><input id="newUserPhone" maxlength="20"></div>` +
      `<div><label for="newUserGender">Género *</label><select id="newUserGender" required><option value="">Selecciona una opción</option><option>Femenino</option><option>Masculino</option><option>Otro</option></select></div>` +
      `<div><label for="newUserPassword">Contraseña inicial * (mínimo 8 caracteres)</label><input id="newUserPassword" type="password" minlength="8" maxlength="200" autocomplete="new-password" required></div>` +
      `<div><label for="newUserPasswordConfirm">Confirmar contraseña *</label><input id="newUserPasswordConfirm" type="password" minlength="8" maxlength="200" autocomplete="new-password" required></div>` +
      `</div><div class="actions"><button type="submit">Crear cuenta</button></div><p id="createUserMsg" class="muted" role="status"></p></form></section>`
    : '';
  return pageHead('Base de datos institucional', 'Explorador de datos disponibles según tu perfil.') +
    createAccountForm +
    `<section class="panel"><div class="panel-head"><h2>Tablas de datos</h2>` +
    `<button class="secondary" id="exportTable">Exportar tabla CSV</button></div>` +
    `<div class="database-tabs">${Object.entries(names).map(([key, name]) =>
      `<button class="${dbTable === key ? 'active' : ''}" data-dbtable="${key}">${esc(name)}</button>`
    ).join('')}</div><input id="dbSearch" placeholder="Buscar en la tabla seleccionada..."/>` +
    '<div id="dbTableContent" class="space-top"></div></section>';
};

renderFamily = function renderConnectedFamily() {
  const guardian = userById(currentUser.id);
  return pageHead('Padres y acudientes', 'Información de acudiente registrada en la base institucional.') +
    `<section class="panel"><h2>Acudiente</h2>` +
    `<p><b>Nombre:</b> ${esc(guardian?.acudiente || 'Sin registrar')}</p>` +
    `<p><b>Parentesco:</b> ${esc(guardian?.parentesco || 'Sin registrar')}</p></section>` +
    '<p class="small-note">Si algún dato está desactualizado, solicita su corrección al administrador de la institución.</p>';
};

renderGrades = function renderConnectedGrades() {
  if (isAdmin()) {
    const noteRows = db.grades.map((grade) => [
      esc(grade.id),
      Number(grade.calificacion).toFixed(2),
      Number(grade.autoevaluacion).toFixed(2),
      Number(grade.coevaluacion).toFixed(2),
      Number(grade.total).toFixed(2),
      badge(grade.estado),
      esc(grade.descripcion)
    ]);
    return pageHead('Calificaciones', 'Registros existentes en Aiven, sin estudiante ni materia asociados.') +
      '<section class="notice">La tabla notas no tiene relaciones de estudiante, docente o materia. Se muestran los campos originales sin atribuirlos a otra persona.</section>' +
      `<section class="panel"><h2>Notas existentes</h2>${table(['ID','Calificación','Autoevaluación','Coevaluación','Total','Estado','Descripción'],noteRows)}</section>`;
  }

  const message = 'La base conectada todavía no relaciona las notas con estudiantes, materias y docentes. Por eso esta sección no muestra ni registra calificaciones hasta que esas relaciones existan.';
  return pageHead('Calificaciones', 'La estructura actual de notas no permite relacionarlas con tu perfil.') +
    `<section class="notice">${esc(message)}</section>`;
};

getTableRows = function getConnectedTableRows() {
  if (dbTable === 'grades') {
    return db.grades.map((grade) => ({
      ID: grade.id,
      Calificación: grade.calificacion,
      Autoevaluación: grade.autoevaluacion,
      Coevaluación: grade.coevaluacion,
      Total: grade.total,
      Estado: grade.estado,
      Descripción: grade.descripcion
    }));
  }
  return getOriginalTableRows();
};

const getOriginalTableRows = getTableRows;

stat = function renderInstitutionalStat(label, value, foot = 'Base institucional') {
  return `<article class="card"><div class="stat-label">${esc(label)}</div>` +
    `<div class="stat-number">${esc(value)}</div><div class="stat-foot">${esc(foot)}</div></article>`;
};

const previousConnectedRenderHome = renderHome;
renderHome = function renderAivenHome() {
  return previousConnectedRenderHome().replace(
    /<section class="notice">[^<]*<\/section>/,
    '<section class="notice">Información cargada desde la base institucional conectada.</section>'
  );
};

(async () => {
  try {
    await apiRequest('/api/health');
    const session = await apiRequest('/api/auth/me');
    if (session.user) await completeLogin(session.user);
  } catch (error) {
    if (!/sesión|autenticada|expiró|válida/i.test(error.message)) {
      $('loginMessage').textContent = 'El servicio institucional no está disponible. Intenta de nuevo más tarde.';
    }
  }
})();
