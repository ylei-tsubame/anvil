const express = require('express');
const { spawnSync } = require('child_process');

const router = express.Router();

router.get('/', (request, response) => {
  console.log('Calling CLI script to get data.');

  const scriptName = 'striker-access-database';
  const childProcess = spawnSync(
    scriptName,
    [
      '--query',
      'SELECT file_uuid, file_name, file_size, file_type, file_md5sum FROM files;',
    ],
    {
      timeout: 10000,
      encoding: 'utf-8',
    },
  );
  let stdoutJSON;

  if (childProcess.error) {
    console.log('Error:', childProcess.error);

    response.status(500).send();
  }

  console.log('Stdout:', childProcess.stdout);
  console.log('Stderr:', childProcess.stderr);

  try {
    stdoutJSON = JSON.parse(childProcess.stdout);
  } catch (jsonParseError) {
    console.warn(`Failed to parse output of script ${scriptName}.`);
  }

  response.status(200).send(stdoutJSON);
});

module.exports = router;
