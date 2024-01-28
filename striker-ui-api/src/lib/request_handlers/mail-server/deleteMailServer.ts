import { RequestHandler } from 'express';

import { execManageAlerts } from '../../execManageAlerts';
import { stderr } from '../../shell';

export const deleteMailServer: RequestHandler<MailServerParamsDictionary> = (
  request,
  response,
) => {
  const {
    params: { uuid },
  } = request;

  try {
    execManageAlerts('mail-servers', 'delete', { uuid });
  } catch (error) {
    stderr(`Failed to delete mail server; CAUSE: ${error}`);

    return response.status(500).send();
  }

  return response.status(204).send();
};
