import { Box, List as MUIList, ListItem as MUIListItem } from '@mui/material';
import { capitalize } from 'lodash';
import { FC, ReactElement } from 'react';

import FlexBox from './FlexBox';
import { BodyText, MonoText, SensitiveText } from './Text';

const capEntryLabel: CapFormEntryLabel = (value) => {
  const spaced = value.replace(/([a-z\d])([A-Z])/g, '$1 $2');
  const lcased = spaced.toLowerCase();

  return capitalize(lcased);
};

const renderEntryValueWithMono: RenderFormValueFunction = ({ entry }) => (
  <MonoText whiteSpace="nowrap">{String(entry)}</MonoText>
);

const renderEntryValueWithPassword: RenderFormValueFunction = (args) => {
  const { entry, key } = args;

  return /passw/i.test(key) ? (
    <SensitiveText
      revealButtonProps={{ sx: { marginRight: 0, padding: 0 } }}
      monospaced
      textLineHeight={null}
    >
      {String(entry)}
    </SensitiveText>
  ) : (
    renderEntryValueWithMono(args)
  );
};

const buildEntryList = ({
  depth = 0,
  entries,
  getEntryLabel,
  getListProps,
  getListItemProps,
  listKey,
  maxDepth,
  renderEntry,
  renderEntryValue,
}: {
  depth?: number;
  entries: FormEntries;
  getEntryLabel: GetFormEntryLabelFunction;
  getListProps?: GetFormEntriesPropsFunction;
  getListItemProps?: GetFormEntryPropsFunction;
  listKey?: string;
  maxDepth: number;
  renderEntry: RenderFormEntryFunction;
  renderEntryValue: RenderFormValueFunction;
}): ReactElement => {
  const result: ReactElement[] = [];

  Object.entries(entries).forEach(([itemKey, entry]) => {
    const itemId = `form-summary-entry-${itemKey}`;

    const nest = entry !== null && typeof entry === 'object';
    const value = nest ? null : entry;

    result.push(
      <MUIListItem
        key={itemId}
        sx={{ paddingLeft: `${depth}em` }}
        {...getListItemProps?.call(null, { depth, entry: value, key: itemKey })}
      >
        {renderEntry({
          depth,
          entry: value,
          getLabel: getEntryLabel,
          key: itemKey,
          nest,
          renderValue: renderEntryValue,
        })}
      </MUIListItem>,
    );

    if (nest && depth < maxDepth) {
      result.push(
        buildEntryList({
          depth: depth + 1,
          entries: entry,
          getEntryLabel,
          listKey: itemKey,
          maxDepth,
          renderEntry,
          renderEntryValue,
        }),
      );
    }
  });

  const listId = `form-summary-list-${listKey ?? 'root'}`;

  return (
    <MUIList
      dense
      disablePadding
      key={listId}
      {...getListProps?.call(null, { depth, entries, key: listKey })}
    >
      {result}
    </MUIList>
  );
};

const FormSummary = <T extends FormEntries>({
  entries,
  getEntryLabel = ({ cap, key }) => cap(key),
  getListProps,
  getListItemProps,
  hasPassword,
  maxDepth = 3,
  renderEntry = ({ depth, entry, getLabel, key, nest, renderValue }) => (
    <FlexBox fullWidth growFirst row maxWidth="100%">
      <BodyText>{getLabel({ cap: capEntryLabel, depth, entry, key })}</BodyText>
      <Box sx={{ maxWidth: '100%', overflowX: 'scroll' }}>
        {!nest && renderValue({ depth, entry, key })}
      </Box>
    </FlexBox>
  ),
  // Prop(s) that rely on other(s).
  renderEntryValue = (args) => {
    const { entry } = args;

    if (['', null, undefined].some((bad) => entry === bad)) {
      return <BodyText>none</BodyText>;
    }

    return hasPassword
      ? renderEntryValueWithPassword(args)
      : renderEntryValueWithMono(args);
  },
}: FormSummaryProps<T>): ReturnType<FC<FormSummaryProps<T>>> =>
  buildEntryList({
    entries,
    getEntryLabel,
    getListProps,
    getListItemProps,
    maxDepth,
    renderEntry,
    renderEntryValue,
  });

export default FormSummary;
