'use strict';

require('dotenv').config();

const bcrypt = require('bcryptjs');
const { createDatabasePool } = require('../db');

async function main() {
  const pool = createDatabasePool();
  try {
    const [users] = await pool.query(
      'SELECT `id_persona`, `contraseña` FROM `persona` ORDER BY `id_persona`'
    );
    let updated = 0;
    let alreadyHashed = 0;

    for (const user of users) {
      if (/^\$2[aby]\$\d{2}\$/.test(user.contraseña)) {
        alreadyHashed += 1;
        continue;
      }
      if (typeof user.contraseña !== 'string' || user.contraseña.length === 0) {
        throw new Error(`La persona ${user.id_persona} no tiene una contraseña válida.`);
      }

      const passwordHash = await bcrypt.hash(user.contraseña, 12);
      await pool.execute(
        'UPDATE `persona` SET `contraseña` = ? WHERE `id_persona` = ?',
        [passwordHash, user.id_persona]
      );
      updated += 1;
    }

    console.log(`Hashes generados: ${updated}. Registros ya protegidos: ${alreadyHashed}.`);
    console.log('Cambia también las contraseñas que se hayan expuesto en volcados SQL.');
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error('No se pudieron proteger las contraseñas:', error.message);
  process.exitCode = 1;
});
