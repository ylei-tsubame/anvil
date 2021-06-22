import { useState, useContext } from 'react';
import {
  List,
  ListItem,
  Divider,
  Box,
  Button,
  Checkbox,
  Menu,
  MenuItem,
} from '@material-ui/core';
import EditIcon from '@material-ui/icons/Edit';
import MoreVertIcon from '@material-ui/icons/MoreVert';
import { makeStyles } from '@material-ui/core/styles';
import { Panel } from './Panels';
import PeriodicFetch from '../lib/fetchers/periodicFetch';
import { HeaderText, BodyText } from './Text';
import { HOVER, DIVIDER } from '../lib/consts/DEFAULT_THEME';
import { AnvilContext } from './AnvilContext';
import serverState from '../lib/consts/SERVERS';
import Decorator, { Colours } from './Decorator';
import Spinner from './Spinner';
import hostsSanitizer from '../lib/sanitizers/hostsSanitizer';

const useStyles = makeStyles((theme) => ({
  root: {
    width: '100%',
    overflow: 'auto',
    height: '78vh',
    [theme.breakpoints.down('md')]: {
      height: '100%',
    },
  },
  divider: {
    background: DIVIDER,
  },
  verticalDivider: {
    height: '75%',
    paddingTop: '1em',
  },
  button: {
    '&:hover': {
      backgroundColor: HOVER,
    },
    paddingLeft: 0,
  },
  headerPadding: {
    paddingLeft: '.3em',
  },
  hostsBox: {
    padding: '1em',
    paddingRight: 0,
  },
  hostBox: {
    paddingTop: 0,
  },
  checkbox: {
    paddingTop: '.8em',
  },
  editButtonBox: {
    paddingTop: '.3em',
  },
  dropdown: {
    paddingTop: '.8em',
    paddingBottom: '.8em',
  },
}));

const selectDecorator = (state: string): Colours => {
  switch (state) {
    case 'running':
      return 'ok';
    case 'shut off':
      return 'off';
    case 'crashed':
      return 'error';
    default:
      return 'warning';
  }
};

const Servers = ({ anvil }: { anvil: AnvilListItem[] }): JSX.Element => {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [showCheckbox, setShowCheckbox] = useState<boolean>(false);
  const [selected, setSelected] = useState<string[]>([]);
  const { uuid } = useContext(AnvilContext);
  const classes = useStyles();

  const { data, isLoading } = PeriodicFetch<AnvilServers>(
    `${process.env.NEXT_PUBLIC_API_URL}/get_servers?anvil_uuid=${uuid}`,
  );

  const handleClick = (event: React.MouseEvent<HTMLButtonElement>): void => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleChange = (server_uuid: string): void => {
    const index = selected.indexOf(server_uuid);
    if (index === -1) {
      selected.push(server_uuid);
      setSelected([...selected]);
    } else selected.splice(index, 1);
  };

  const isSelected = (server: string): boolean => {
    const thing = selected.find((s) => s === server);
    return thing !== 'undefined';
  };

  const anvilIndex = anvil.findIndex((a) => a.anvil_uuid === uuid);

  const filteredHosts = hostsSanitizer(anvil[anvilIndex]?.hosts);

  return (
    <Panel>
      <Box className={classes.headerPadding} display="flex">
        <Box flexGrow={1}>
          <HeaderText text="Servers" />
        </Box>
        <Box className={classes.editButtonBox}>
          <Button
            variant="contained"
            color="secondary"
            startIcon={<EditIcon />}
            onClick={() => setShowCheckbox(!showCheckbox)}
          />
        </Box>
      </Box>
      {showCheckbox && (
        <Box className={classes.headerPadding} display="flex">
          <Box flexGrow={1} className={classes.dropdown}>
            <Button
              variant="contained"
              color="secondary"
              startIcon={<MoreVertIcon />}
              onClick={handleClick}
            >
              <BodyText text="Power" />
            </Button>
            <Menu
              id="simple-menu"
              anchorEl={anchorEl}
              keepMounted
              open={Boolean(anchorEl)}
              onClose={handleClose}
            >
              <MenuItem onClick={handleClose}>
                <BodyText text="On" />
              </MenuItem>
              <MenuItem onClick={handleClose}>
                <BodyText text="Off" />
              </MenuItem>
            </Menu>
          </Box>
        </Box>
      )}
      {!isLoading ? (
        <Box className={classes.root}>
          <List component="nav">
            {data &&
              data.servers.map((server: AnvilServer) => {
                return (
                  <>
                    <ListItem
                      button
                      className={classes.button}
                      key={server.server_uuid}
                    >
                      <Box display="flex" flexDirection="row" width="100%">
                        {showCheckbox && (
                          <Box className={classes.checkbox}>
                            <Checkbox
                              key={server.server_uuid}
                              checked={isSelected(server.server_uuid)}
                              onChange={() => handleChange(server.server_uuid)}
                              inputProps={{ 'aria-label': 'primary checkbox' }}
                            />
                          </Box>
                        )}
                        <Box p={1}>
                          <Decorator
                            colour={selectDecorator(server.server_state)}
                          />
                        </Box>
                        <Box p={1} flexGrow={1}>
                          <BodyText text={server.server_name} />
                          <BodyText
                            text={
                              serverState.get(server.server_state) ||
                              'Not Available'
                            }
                          />
                        </Box>
                        <Box display="flex" className={classes.hostsBox}>
                          {server.server_state !== 'shut off' &&
                            server.server_state !== 'crashed' &&
                            filteredHosts.map(
                              (
                                host: AnvilStatusHost,
                                index: number,
                              ): JSX.Element => (
                                <>
                                  <Box
                                    p={1}
                                    key={host.host_uuid}
                                    className={classes.hostBox}
                                  >
                                    <BodyText
                                      text={host.host_name}
                                      selected={
                                        server.server_host_uuid ===
                                        host.host_uuid
                                      }
                                    />
                                  </Box>
                                  {index !== filteredHosts.length - 1 && (
                                    <Divider
                                      className={`${classes.divider} ${classes.verticalDivider}`}
                                      orientation="vertical"
                                    />
                                  )}
                                </>
                              ),
                            )}
                        </Box>
                      </Box>
                    </ListItem>
                    <Divider className={classes.divider} />
                  </>
                );
              })}
          </List>
        </Box>
      ) : (
        <Spinner />
      )}
    </Panel>
  );
};

export default Servers;
