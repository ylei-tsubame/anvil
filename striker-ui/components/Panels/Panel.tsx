import { ReactNode } from 'react';
import { makeStyles } from '@material-ui/core/styles';
import { PANEL_BACKGROUND, TEXT } from '../../lib/consts/DEFAULT_THEME';

type Props = {
  children: ReactNode;
};

const useStyles = makeStyles(() => ({
  paper: {
    padding: '2.1em',
    backgroundColor: PANEL_BACKGROUND,
    opacity: 0.8,
    zIndex: 999,
  },
  container: {
    margin: '1em',
    position: 'relative',
  },
  square: {
    content: '""',
    position: 'absolute',
    width: '2.1em',
    height: '2.1em',
    border: '1px',
    borderColor: TEXT,
    borderWidth: '1px',
    borderRadius: '3px',
    borderStyle: 'solid',
    padding: 0,
    margin: 0,
  },
  topSquare: {
    top: '-0.3em',
    left: '-0.3em',
  },
  bottomSquare: {
    bottom: '-0.3em',
    right: '-0.3em',
  },
}));

const Panel = ({ children }: Props): JSX.Element => {
  const classes = useStyles();

  return (
    <div className={classes.container}>
      <div className={`${classes.square} ${classes.topSquare}`} />
      <div className={`${classes.square} ${classes.bottomSquare}`} />
      <div className={classes.paper}>{children}</div>
    </div>
  );
};

export default Panel;
