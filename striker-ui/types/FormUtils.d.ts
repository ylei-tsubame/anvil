type FormValidity<T> = {
  [K in keyof T]?: boolean;
};

type InputTestBatchFinishCallbackBuilder<M extends MapToInputTestID> = (
  key: keyof M,
) => InputTestBatchFinishCallback;

type InputFirstRenderFunctionArgs = { isValid: boolean };

type InputFirstRenderFunction = (args: InputFirstRenderFunctionArgs) => void;

type InputFirstRenderFunctionBuilder<M extends MapToInputTestID> = (
  key: keyof M,
) => InputFirstRenderFunction;

type InputUnmountFunction = () => void;

type InputUnmountFunctionBuilder<M extends MapToInputTestID> = (
  key: keyof M,
) => InputUnmountFunction;

type FormUtils<M extends MapToInputTestID> = {
  buildFinishInputTestBatchFunction: InputTestBatchFinishCallbackBuilder<M>;
  buildInputFirstRenderFunction: InputFirstRenderFunctionBuilder<M>;
  buildInputUnmountFunction: InputUnmountFunctionBuilder<M>;
  formValidity: FormValidity<M>;
  isFormInvalid: boolean;
  setFormValidity: import('react').Dispatch<
    import('react').SetStateAction<FormValidity<M>>
  >;
  setMessage: (key: keyof M, message?: Message) => void;
  setMessageRe: (re: RegExp, message?: Message) => void;
  setValidity: (key: keyof M, value?: boolean) => void;
  setValidityRe: (re: RegExp, value?: boolean) => void;
  unsetKey: (key: keyof M) => void;
  unsetKeyRe: (re: RegExp) => void;
};
