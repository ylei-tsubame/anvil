import { Grid } from '@material-ui/core';
import { makeStyles } from '@material-ui/core/styles';

import Anvils from '../components/Anvils';
import Nodes from '../components/Nodes';
import CPU from '../components/CPU';
import SharedStorage from '../components/SharedStorage';
import ReplicatedStorage from '../components/ReplicatedStorage';
import Memory from '../components/Memory';
import PeriodicFetch from '../lib/fetchers/periodicFetch';

const useStyles = makeStyles(() => ({
  grid: {
    height: '100vh',
  },
}));

const Home = (): JSX.Element => {
  const classes = useStyles();

  const { data } = PeriodicFetch<AnvilList>(
    'http://localhost:8080',
    '/anvils/get_anvils',
  );

  return (
    <Grid container alignItems="center" justify="space-around">
      <Grid item xs={3}>
        <Grid
          container
          justify="flex-start"
          direction="column"
          className={classes.grid}
        >
          <Anvils list={data} />
          <Nodes />
        </Grid>
      </Grid>
      <Grid item xs={5}>
        <Grid
          container
          justify="flex-start"
          direction="column"
          className={classes.grid}
        >
          <ReplicatedStorage />
        </Grid>
      </Grid>
      <Grid item xs={3}>
        <Grid
          container
          justify="flex-start"
          direction="column"
          className={classes.grid}
        >
          <SharedStorage
            anvil={data?.anvils?.length > 0 ? data.anvils[0] : 'no uuid'}
          />
          <CPU
            uuid={
              data?.anvils?.length > 0 ? data.anvils[0].anvil_uuid : 'no uuid'
            }
          />
          <Memory
            uuid={
              data?.anvils?.length > 0 ? data.anvils[0].anvil_uuid : 'no uuid'
            }
          />
        </Grid>
      </Grid>
    </Grid>
  );
};

export default Home;
