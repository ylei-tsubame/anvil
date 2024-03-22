import { getgid, getuid, setgid, setuid } from 'process';

import { PGID, PUID, PORT, ECODE_DROP_PRIVILEGES } from './lib/consts';

import { access } from './lib/accessModule';
import { stderr, stdout } from './lib/shell';

/**
 * Wait until the anvil-access-module daemon finishes its setup before doing
 * anything else.
 *
 * Notes:
 * * The webpackMode directive tells webpack to include the dynamic module into
 *   the main bundle. Webpack defaults to put such modules in separate files to
 *   reduce the amount of loading.
 */
access.once('active', async () => {
  const { default: app } = await import(/* webpackMode: "eager" */ './app');
  const { proxyServerVncUpgrade } = await import(
    /* webpackMode: "eager" */ './middlewares'
  );

  stdout(`Starting main process with ownership ${getuid()}:${getgid()}`);

  const server = (await app).listen(PORT, () => {
    try {
      // Group must be set before user to avoid permission error.
      setgid(PGID);
      setuid(PUID);

      stdout(`Main process ownership changed to ${getuid()}:${getgid()}.`);
    } catch (error) {
      stderr(`Failed to change main process ownership; CAUSE: ${error}`);

      process.exit(ECODE_DROP_PRIVILEGES);
    }

    stdout(`Listening on localhost:${PORT}.`);
  });

  server.on('upgrade', proxyServerVncUpgrade);
});
