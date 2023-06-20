import anvilRouter from './anvil';
import authRouter from './auth';
import commandRouter from './command';
import echoRouter from './echo';
import fenceRouter from './fence';
import fileRouter from './file';
import hostRouter from './host';
import jobRouter from './job';
import manifestRouter from './manifest';
import networkInterfaceRouter from './network-interface';
import serverRouter from './server';
import sshKeyRouter from './ssh-key';
import staticRouter from './static';
import upsRouter from './ups';
import userRouter from './user';

const routes = {
  private: {
    anvil: anvilRouter,
    command: commandRouter,
    fence: fenceRouter,
    file: fileRouter,
    host: hostRouter,
    job: jobRouter,
    manifest: manifestRouter,
    'network-interface': networkInterfaceRouter,
    server: serverRouter,
    'ssh-key': sshKeyRouter,
    ups: upsRouter,
    user: userRouter,
  },
  public: {
    auth: authRouter,
    echo: echoRouter,
  },
  static: staticRouter,
};

export default routes;
