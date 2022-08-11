import { Grid as MUIGrid } from '@mui/material';
import {
  forwardRef,
  ReactNode,
  useCallback,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from 'react';
import { v4 as uuidv4 } from 'uuid';

import INPUT_TYPES from '../lib/consts/INPUT_TYPES';

import FlexBox from './FlexBox';
import InputWithRef, { InputForwardedRefContent } from './InputWithRef';
import isEmpty from '../lib/isEmpty';
import MessageBox, { Message } from './MessageBox';
import OutlinedInputWithLabel, {
  OutlinedInputWithLabelProps,
} from './OutlinedInputWithLabel';
import pad from '../lib/pad';
import SuggestButton from './SuggestButton';
import { testInput, testLength, testNotBlank } from '../lib/test_input';
import { InputTestBatches } from '../types/TestInputFunction';

type GeneralInitFormForwardRefContent = {
  get?: () => {
    adminPassword?: string;
    domainName?: string;
    hostName?: string;
    hostNumber?: number;
    organizationName?: string;
    organizationPrefix?: string;
  };
};

type OutlinedInputWithLabelOnBlur = Exclude<
  OutlinedInputWithLabelProps['inputProps'],
  undefined
>['onBlur'];

const MAX_ORGANIZATION_PREFIX_LENGTH = 5;
const MIN_ORGANIZATION_PREFIX_LENGTH = 1;
const MAX_HOST_NUMBER_LENGTH = 2;
const INPUT_COUNT = 7;
const REP_DN_CHAR = /^[a-z0-9-.]+$/;

const MAP_TO_ORGANIZATION_PREFIX_BUILDER: Record<
  number,
  (words: string[]) => string
> = {
  0: () => '',
  1: ([word]) =>
    word.substring(0, MIN_ORGANIZATION_PREFIX_LENGTH).toLocaleLowerCase(),
  2: (words) =>
    words.map((word) => word.substring(0, 1).toLocaleLowerCase()).join(''),
};

const INPUT_TEST_MESSAGE_KEYS: string[] = Array.from(
  {
    length: INPUT_COUNT,
  },
  () => uuidv4(),
);

const buildOrganizationPrefix = (organizationName = '') => {
  const words: string[] = organizationName
    .split(/\s/)
    .filter((word) => !/and|of/.test(word))
    .slice(0, MAX_ORGANIZATION_PREFIX_LENGTH);

  const builderKey: number = words.length > 1 ? 2 : words.length;

  return MAP_TO_ORGANIZATION_PREFIX_BUILDER[builderKey](words);
};

const buildHostName = ({
  organizationPrefix,
  hostNumber,
  domainName,
}: {
  organizationPrefix?: string;
  hostNumber?: number;
  domainName?: string;
}) =>
  isEmpty([organizationPrefix, hostNumber, domainName], { not: true })
    ? `${organizationPrefix}-striker${pad(hostNumber)}.${domainName}`
    : '';

const GeneralInitForm = forwardRef<GeneralInitFormForwardRefContent>(
  (generalInitFormProps, ref) => {
    const [helpMessage, setHelpMessage] = useState<ReactNode | undefined>();
    const [inputMessages, setInputMessages] = useState<
      Array<Message | undefined>
    >([]);
    const [
      isShowOrganizationPrefixSuggest,
      setIsShowOrganizationPrefixSuggest,
    ] = useState<boolean>(false);
    const [isShowHostNameSuggest, setIsShowHostNameSuggest] =
      useState<boolean>(false);
    const [isConfirmAdminPassword, setIsConfirmAdminPassword] =
      useState<boolean>(true);

    const adminPasswordInputRef = useRef<InputForwardedRefContent<'string'>>(
      {},
    );
    const confirmAdminPasswordInputRef = useRef<
      InputForwardedRefContent<'string'>
    >({});
    const organizationNameInputRef = useRef<InputForwardedRefContent<'string'>>(
      {},
    );
    const organizationPrefixInputRef = useRef<
      InputForwardedRefContent<'string'>
    >({});
    const domainNameInputRef = useRef<InputForwardedRefContent<'string'>>({});
    const hostNumberInputRef = useRef<InputForwardedRefContent<'number'>>({});
    const hostNameInputRef = useRef<InputForwardedRefContent<'string'>>({});

    const setInputMessage = useCallback((index: number, message?: Message) => {
      setInputMessages((previous) => {
        previous.splice(index, 1, message);
        return [...previous];
      });
    }, []);
    const setOrganizationPrefixInputMessage = useCallback(
      (message?: Message) => setInputMessage(1, message),
      [setInputMessage],
    );
    const setHostNumberInputMessage = useCallback(
      (message?: Message) => setInputMessage(2, message),
      [setInputMessage],
    );
    const setDomainNameInputMessage = useCallback(
      (message?: Message) => setInputMessage(3, message),
      [setInputMessage],
    );
    const setHostNameInputMessage = useCallback(
      (message?: Message) => setInputMessage(4, message),
      [setInputMessage],
    );
    const setAdminPasswordInputMessage = useCallback(
      (message?: Message) => setInputMessage(5, message),
      [setInputMessage],
    );
    const setConfirmAdminPasswordInputMessage = useCallback(
      (message?: Message) => setInputMessage(6, message),
      [setInputMessage],
    );
    const createInputTestMessages = useCallback(
      () =>
        inputMessages.map((message, index) => {
          let messageElement;

          if (message) {
            const { children, type = 'warning' } = message;

            messageElement = (
              <MessageBox
                key={`input-test-message-${INPUT_TEST_MESSAGE_KEYS[index]}`}
                type={type}
              >
                {children}
              </MessageBox>
            );
          }

          return messageElement;
        }),
      [inputMessages],
    );
    const populateOrganizationPrefixInput = useCallback(
      ({
        organizationName = organizationNameInputRef.current.getValue?.call(
          null,
        ),
      } = {}) => {
        const organizationPrefix = buildOrganizationPrefix(organizationName);

        organizationPrefixInputRef.current.setValue?.call(
          null,
          organizationPrefix,
        );

        return organizationPrefix;
      },
      [],
    );
    const populateHostNameInput = useCallback(
      ({
        organizationPrefix = organizationPrefixInputRef.current.getValue?.call(
          null,
        ),
        hostNumber = hostNumberInputRef.current.getValue?.call(null),
        domainName = domainNameInputRef.current.getValue?.call(null),
      } = {}) => {
        const hostName = buildHostName({
          organizationPrefix,
          hostNumber,
          domainName,
        });

        hostNameInputRef.current.setValue?.call(null, hostName);

        return hostName;
      },
      [],
    );
    const isOrganizationPrefixPrereqFilled = useCallback(
      () =>
        isEmpty([organizationNameInputRef.current.getValue?.call(null)], {
          not: true,
        }),
      [],
    );
    const isHostNamePrereqFilled = useCallback(
      () =>
        isEmpty(
          [
            organizationPrefixInputRef.current.getValue?.call(null),
            hostNumberInputRef.current.getValue?.call(null),
            domainNameInputRef.current.getValue?.call(null),
          ],
          {
            not: true,
          },
        ),
      [],
    );
    const populateOrganizationPrefixInputOnBlur: OutlinedInputWithLabelOnBlur =
      useCallback(() => {
        if (organizationPrefixInputRef.current.getIsChangedByUser?.call(null)) {
          setIsShowOrganizationPrefixSuggest(
            isOrganizationPrefixPrereqFilled(),
          );
        } else {
          populateOrganizationPrefixInput();
        }
      }, [isOrganizationPrefixPrereqFilled, populateOrganizationPrefixInput]);
    const populateHostNameInputOnBlur: OutlinedInputWithLabelOnBlur =
      useCallback(() => {
        if (hostNameInputRef.current.getIsChangedByUser?.call(null)) {
          setIsShowHostNameSuggest(isHostNamePrereqFilled());
        } else {
          populateHostNameInput();
        }
      }, [isHostNamePrereqFilled, populateHostNameInput]);
    const handleOrganizationPrefixSuggest = useCallback(() => {
      const organizationPrefix = populateOrganizationPrefixInput();

      if (!hostNameInputRef.current.getIsChangedByUser?.call(null)) {
        populateHostNameInput({ organizationPrefix });
      }
    }, [populateHostNameInput, populateOrganizationPrefixInput]);
    const handlerHostNameSuggest = useCallback(() => {
      populateHostNameInput();
    }, [populateHostNameInput]);
    const buildHelpMessage = useCallback(
      (text: string) => (previous?: string) =>
        previous === text ? undefined : text,
      [],
    );

    const inputTests: InputTestBatches = useMemo(
      () => ({
        adminPassword: {
          defaults: {
            onSuccess: () => {
              setAdminPasswordInputMessage(undefined);
            },
          },
          tests: [
            {
              onFailure: () => {
                setAdminPasswordInputMessage({
                  children:
                    'Admin password cannot contain single-quote, double-quote, slash, backslash, angle brackets, and curly brackets.',
                });
              },
              test: ({ value }) => !/['"/\\><}{]/g.test(value as string),
            },
          ],
        },
        confirmAdminPassword: {
          defaults: {
            onSuccess: () => {
              setConfirmAdminPasswordInputMessage(undefined);
            },
          },
          tests: [
            {
              onFailure: () => {
                setConfirmAdminPasswordInputMessage({
                  children: 'Admin password confirmation failed.',
                });
              },
              test: ({ value, compare }) => value === compare,
            },
          ],
        },
        domainName: {
          defaults: {
            onSuccess: () => {
              setDomainNameInputMessage(undefined);
            },
          },
          tests: [
            {
              onFailure: () => {
                setDomainNameInputMessage({
                  children:
                    'Domain name can only contain lowercase alphanumeric, hyphen, and decimal characters.',
                });
              },
              test: ({ value }) => REP_DN_CHAR.test(value as string),
            },
          ],
        },
        hostName: {
          defaults: {
            onSuccess: () => {
              setHostNameInputMessage(undefined);
            },
          },
          tests: [
            {
              onFailure: () => {
                setHostNameInputMessage({
                  children:
                    'Host name can only contain lowercase alphanumeric, hyphen, and decimal characters.',
                });
              },
              test: ({ value }) => REP_DN_CHAR.test(value as string),
            },
          ],
        },
        hostNumber: {
          defaults: {
            onSuccess: () => {
              setHostNumberInputMessage(undefined);
            },
          },
          tests: [
            {
              onFailure: () => {
                setHostNumberInputMessage({
                  children: 'Host number can only contain digits.',
                });
              },
              test: ({ value }) => /^\d+$/.test(value as string),
            },
          ],
        },
        organizationName: {
          tests: [{ test: testNotBlank }],
        },
        organizationPrefix: {
          defaults: {
            onSuccess: () => {
              setOrganizationPrefixInputMessage(undefined);
            },
          },
          tests: [
            {
              onFailure: ({ max, min }) => {
                setOrganizationPrefixInputMessage({
                  children: `Organization prefix must be ${min} to ${max} characters.`,
                });
              },
              test: testLength,
            },
            {
              onFailure: () => {
                setOrganizationPrefixInputMessage({
                  children:
                    'Organization prefix can only contain lowercase alphanumeric characters.',
                });
              },
              test: ({ value }) => /^[a-z0-9]+$/.test(value as string),
            },
          ],
        },
      }),
      [
        setAdminPasswordInputMessage,
        setConfirmAdminPasswordInputMessage,
        setDomainNameInputMessage,
        setHostNameInputMessage,
        setHostNumberInputMessage,
        setOrganizationPrefixInputMessage,
      ],
    );

    useImperativeHandle(ref, () => ({
      get: () => ({
        adminPassword: adminPasswordInputRef.current.getValue?.call(null),
        organizationName: organizationNameInputRef.current.getValue?.call(null),
        organizationPrefix:
          organizationPrefixInputRef.current.getValue?.call(null),
        domainName: domainNameInputRef.current.getValue?.call(null),
        hostNumber: hostNumberInputRef.current.getValue?.call(null),
        hostName: hostNameInputRef.current.getValue?.call(null),
      }),
    }));

    return (
      <FlexBox>
        <MUIGrid columns={{ xs: 1, sm: 2, md: 3 }} container spacing="1em">
          <MUIGrid item xs={1}>
            <FlexBox>
              <InputWithRef
                input={
                  <OutlinedInputWithLabel
                    id="striker-init-general-organization-name"
                    inputProps={{
                      onBlur: populateOrganizationPrefixInputOnBlur,
                    }}
                    inputLabelProps={{ isNotifyRequired: true }}
                    label="Organization name"
                    onChange={({ target: { value } }) => {
                      testInput({
                        inputs: { organizationName: { value } },
                        tests: inputTests,
                      });
                    }}
                    onHelp={() => {
                      setHelpMessage(
                        buildHelpMessage(
                          'Name of the organization that maintains this Anvil! system. You can enter anything that makes sense to you.',
                        ),
                      );
                    }}
                  />
                }
                ref={organizationNameInputRef}
              />
              <FlexBox
                row
                sx={{
                  '& > :first-child': {
                    flexGrow: 1,
                  },
                }}
              >
                <InputWithRef
                  input={
                    <OutlinedInputWithLabel
                      id="striker-init-general-organization-prefix"
                      inputProps={{
                        endAdornment: (
                          <SuggestButton
                            show={isShowOrganizationPrefixSuggest}
                            onClick={handleOrganizationPrefixSuggest}
                          />
                        ),
                        inputProps: {
                          maxLength: MAX_ORGANIZATION_PREFIX_LENGTH,
                          sx: {
                            minWidth: '2.5em',
                          },
                        },
                        onBlur: populateHostNameInputOnBlur,
                      }}
                      inputLabelProps={{ isNotifyRequired: true }}
                      label="Prefix"
                      onChange={({ target: { value } }) => {
                        testInput({
                          inputs: {
                            organizationPrefix: {
                              max: MAX_ORGANIZATION_PREFIX_LENGTH,
                              min: MIN_ORGANIZATION_PREFIX_LENGTH,
                              value,
                            },
                          },
                          tests: inputTests,
                        });

                        setIsShowOrganizationPrefixSuggest(
                          isOrganizationPrefixPrereqFilled(),
                        );
                      }}
                      onHelp={() => {
                        setHelpMessage(
                          buildHelpMessage(
                            "Alphanumberic short-form of the organization name. It's used as the prefix for host names.",
                          ),
                        );
                      }}
                    />
                  }
                  ref={organizationPrefixInputRef}
                />
                <InputWithRef
                  input={
                    <OutlinedInputWithLabel
                      id="striker-init-general-host-number"
                      inputProps={{
                        inputProps: {
                          maxLength: MAX_HOST_NUMBER_LENGTH,
                          sx: {
                            minWidth: '2em',
                          },
                        },
                        onBlur: populateHostNameInputOnBlur,
                      }}
                      inputLabelProps={{ isNotifyRequired: true }}
                      label="Striker #"
                      onChange={({ target: { value } }) => {
                        testInput({
                          inputs: { hostNumber: { value } },
                          tests: inputTests,
                        });
                      }}
                      onHelp={() => {
                        setHelpMessage(
                          buildHelpMessage(
                            "Number or count of this striker; this should be '1' for the first striker, '2' for the second striker, and such.",
                          ),
                        );
                      }}
                    />
                  }
                  ref={hostNumberInputRef}
                  valueType="number"
                />
              </FlexBox>
            </FlexBox>
          </MUIGrid>
          <MUIGrid item xs={1}>
            <FlexBox>
              <InputWithRef
                input={
                  <OutlinedInputWithLabel
                    id="striker-init-general-domain-name"
                    inputProps={{
                      onBlur: populateHostNameInputOnBlur,
                    }}
                    inputLabelProps={{ isNotifyRequired: true }}
                    label="Domain name"
                    onChange={({ target: { value } }) => {
                      testInput({
                        inputs: { domainName: { value } },
                        tests: inputTests,
                      });
                    }}
                    onHelp={() => {
                      setHelpMessage(
                        buildHelpMessage(
                          "Domain name for this striker. It's also the default domain used when creating new install manifests.",
                        ),
                      );
                    }}
                  />
                }
                ref={domainNameInputRef}
              />

              <InputWithRef
                input={
                  <OutlinedInputWithLabel
                    id="striker-init-general-host-name"
                    inputProps={{
                      endAdornment: (
                        <SuggestButton
                          show={isShowHostNameSuggest}
                          onClick={handlerHostNameSuggest}
                        />
                      ),
                    }}
                    inputLabelProps={{ isNotifyRequired: true }}
                    label="Host name"
                    onChange={({ target: { value } }) => {
                      testInput({
                        inputs: { hostName: { value } },
                        tests: inputTests,
                      });

                      setIsShowHostNameSuggest(isHostNamePrereqFilled());
                    }}
                    onHelp={() => {
                      setHelpMessage(
                        buildHelpMessage(
                          "Host name for this striker. It's usually a good idea to use the auto-generated value.",
                        ),
                      );
                    }}
                  />
                }
                ref={hostNameInputRef}
              />
            </FlexBox>
          </MUIGrid>
          <MUIGrid item xs={1} sm={2} md={1}>
            <MUIGrid
              columns={{ xs: 1, sm: 2, md: 1 }}
              container
              spacing="1em"
              sx={{
                '& > * > *': {
                  width: '100%',
                },
              }}
            >
              <MUIGrid item xs={1}>
                <InputWithRef
                  input={
                    <OutlinedInputWithLabel
                      id="striker-init-general-admin-password"
                      inputProps={{
                        inputProps: {
                          type: INPUT_TYPES.password,
                        },
                        onPasswordVisibilityAppend: (inputType) => {
                          setIsConfirmAdminPassword(
                            inputType === INPUT_TYPES.password,
                          );
                        },
                      }}
                      inputLabelProps={{ isNotifyRequired: true }}
                      label="Admin password"
                      onChange={({ target: { value } }) => {
                        testInput({
                          inputs: { adminPassword: { value } },
                          tests: inputTests,
                        });
                      }}
                      onHelp={() => {
                        setHelpMessage(
                          buildHelpMessage(
                            "Password use to login to this Striker and connect to its database. Don't provide an used password here because it'll be stored as plaintext.",
                          ),
                        );
                      }}
                    />
                  }
                  ref={adminPasswordInputRef}
                />
              </MUIGrid>
              {isConfirmAdminPassword && (
                <MUIGrid item xs={1}>
                  <InputWithRef
                    input={
                      <OutlinedInputWithLabel
                        id="striker-init-general-confirm-admin-password"
                        inputProps={{
                          inputProps: {
                            type: INPUT_TYPES.password,
                          },
                        }}
                        inputLabelProps={{
                          isNotifyRequired: isConfirmAdminPassword,
                        }}
                        label="Confirm password"
                        onChange={({ target: { value } }) => {
                          testInput({
                            inputs: {
                              confirmAdminPassword: {
                                value,
                                compare:
                                  adminPasswordInputRef.current.getValue?.call(
                                    null,
                                  ),
                              },
                            },
                            tests: inputTests,
                          });
                        }}
                      />
                    }
                    ref={confirmAdminPasswordInputRef}
                  />
                </MUIGrid>
              )}
            </MUIGrid>
          </MUIGrid>
        </MUIGrid>
        {createInputTestMessages()}
        {helpMessage && (
          <MessageBox
            onClose={() => {
              setHelpMessage(undefined);
            }}
          >
            {helpMessage}
          </MessageBox>
        )}
      </FlexBox>
    );
  },
);

GeneralInitForm.displayName = 'GeneralInitForm';

export type { GeneralInitFormForwardRefContent };

export default GeneralInitForm;
