import busboy from 'busboy';
import { RequestHandler } from 'express';
import fs from 'fs';
import path from 'path';

import SERVER_PATHS from '../lib/consts/SERVER_PATHS';

import { stdout, stdoutVar } from '../lib/shell';

const file =
  ({ dir }: { dir: string }): RequestHandler =>
  (request, response, next) => {
    stdout(`Begin receiving file(s)`);

    const { headers } = request;
    const bb = busboy({ headers });
    const files: FileInfoAppend[] = [];

    bb.on('file', (name, file, info) => {
      stdout(`On busboy file event`);

      const { filename } = info;
      const fInfoAppend: FileInfoAppend = {
        info,
        path: path.join(dir, filename),
      };

      stdoutVar({ fInfoAppend }, 'Received file: ');

      file.pipe(fs.createWriteStream(fInfoAppend.path));
      files.push(fInfoAppend);
    });

    bb.on('close', () => {
      stdoutVar(files, `On busboy close event; files=`);

      request.files = files;

      next();
    });

    bb.on('error', (error) => {
      next(error);
    });

    return request.pipe(bb);
  };

export const handleSharedFile = file({
  dir: SERVER_PATHS.mnt.shared.incoming.self,
});

export default file;
