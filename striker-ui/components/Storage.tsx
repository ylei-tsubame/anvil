import { Grid } from '@mui/material';
import * as prettyBytes from 'pretty-bytes';
import { Panel } from './Panels';
import { AllocationBar } from './Bars';
import { HeaderText, BodyText } from './Text';
import periodicFetch from '../lib/fetchers/periodicFetch';

const Storage = ({ uuid }: { uuid: string }): JSX.Element => {
  const { data, isLoading } = periodicFetch<AnvilMemory>(
    `${process.env.NEXT_PUBLIC_API_URL}/get_memory?anvil_uuid=${uuid}`,
  );

  const memoryData = isLoading || !data ? { total: 0, free: 0 } : data;

  return (
    <Panel>
      <Grid container alignItems="center" justifyContent="space-around">
        <Grid item xs={12}>
          <HeaderText text="Storage Resync" />
        </Grid>
        <Grid item xs={5}>
          <BodyText
            text={`Allocated: ${prettyBytes.default(
              memoryData.total - memoryData.free,
              {
                binary: true,
              },
            )}`}
          />
        </Grid>
        <Grid item xs={4}>
          <BodyText
            text={`Free: ${prettyBytes.default(memoryData.free, {
              binary: true,
            })}`}
          />
        </Grid>
        <Grid item xs={10}>
          <AllocationBar
            allocated={
              ((memoryData.total - memoryData.free) / memoryData.total) * 100
            }
          />
        </Grid>
      </Grid>
    </Panel>
  );
};

export default Storage;
