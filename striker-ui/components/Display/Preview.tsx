import { Dispatch, SetStateAction, useEffect, useState } from 'react';
import { Box, IconButton, styled } from '@mui/material';
import {
  DesktopWindows as DesktopWindowsIcon,
  PowerOffOutlined as PowerOffOutlinedIcon,
} from '@mui/icons-material';

import { BLACK, GREY, TEXT } from '../../lib/consts/DEFAULT_THEME';

import { Panel } from '../Panels';
import { HeaderText } from '../Text';

const PREFIX = 'Preview';

const classes = {
  displayBox: `${PREFIX}-displayBox`,
  fullScreenButton: `${PREFIX}-fullScreenButton`,
  fullScreenBox: `${PREFIX}-fullScreenBox`,
  imageButton: `${PREFIX}-imageButton`,
  powerOffIcon: `${PREFIX}-powerOffIcon`,
  previewImage: `${PREFIX}-previewImage`,
};

const StyledDiv = styled('div')(() => ({
  [`& .${classes.displayBox}`]: {
    padding: 0,
    paddingTop: '.7em',
    width: '100%',
  },

  [`& .${classes.fullScreenButton}`]: {
    borderRadius: 8,
    backgroundColor: TEXT,
    '&:hover': {
      backgroundColor: TEXT,
    },
  },

  [`& .${classes.fullScreenBox}`]: {
    paddingLeft: '1em',
    padding: 0,
  },

  [`& .${classes.imageButton}`]: {
    padding: 0,
    color: TEXT,
  },

  [`& .${classes.powerOffIcon}`]: {
    borderRadius: 8,
    padding: 0,
    color: GREY,
    width: '100%',
    height: '100%',
  },

  [`& .${classes.previewImage}`]: {
    width: '100%',
    height: '100%',
  },
}));

interface PreviewProps {
  setMode: Dispatch<SetStateAction<boolean>>;
  uuid: string;
  serverName: string | string[] | undefined;
}

const Preview = ({ setMode, uuid, serverName }: PreviewProps): JSX.Element => {
  const [preview, setPreview] = useState<string>();

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL}/get_server_screenshot?server_uuid=${uuid}`,
          {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json',
            },
          },
        );
        const { screenshot } = await res.json();
        setPreview(screenshot);
      } catch {
        setPreview('');
      }
    })();
  }, [uuid]);

  return (
    <Panel>
      <StyledDiv>
        <Box flexGrow={1}>
          <HeaderText text={`Server: ${serverName}`} />
        </Box>
        <Box display="flex" className={classes.displayBox}>
          <Box>
            <IconButton
              className={classes.imageButton}
              style={{ color: BLACK }}
              component="span"
              onClick={() => setMode(false)}
            >
              {!preview ? (
                <PowerOffOutlinedIcon className={classes.powerOffIcon} />
              ) : (
                <img
                  alt=""
                  key="preview"
                  src={`data:image/png;base64,${preview}`}
                  className={classes.previewImage}
                />
              )}
            </IconButton>
          </Box>
          <Box className={classes.fullScreenBox}>
            <IconButton
              className={classes.fullScreenButton}
              style={{ color: BLACK }}
              component="span"
              onClick={() => setMode(false)}
            >
              <DesktopWindowsIcon />
            </IconButton>
          </Box>
        </Box>
      </StyledDiv>
    </Panel>
  );
};

export default Preview;
