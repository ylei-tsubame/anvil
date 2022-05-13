import { MinimalInputTestArgs } from '../../types/TestInputFunction';

const testMax: (args: MinimalInputTestArgs) => boolean = ({ max, min }) =>
  max >= min;

export default testMax;
