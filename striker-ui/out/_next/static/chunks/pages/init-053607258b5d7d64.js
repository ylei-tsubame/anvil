(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[464],{593:function(e,n,t){(window.__NEXT_P=window.__NEXT_P||[]).push(["/init",function(){return t(8616)}])},4069:function(e,n,t){"use strict";t.d(n,{Z:function(){return y}});var r=t(7294),i=t(3675),o=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},n=e.postSet,t=e.preSet,r=e.set,o=e.setType,l=void 0===o?"string":o,u=e.valueKey,a=void 0===u?"value":u;return function(e){var o=e.target[a],u=i.Z[l](o);null===t||void 0===t||t.call(null,e),null===r||void 0===r||r.call(null,u),null===n||void 0===n||n.call(null,e)}},l=t(7987);function u(e,n){(null==n||n>e.length)&&(n=e.length);for(var t=0,r=new Array(n);t<n;t++)r[t]=e[t];return r}function a(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function c(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{},r=Object.keys(t);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(t).filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable})))),r.forEach((function(n){a(e,n,t[n])}))}return e}function s(e,n){if(null==e)return{};var t,r,i=function(e,n){if(null==e)return{};var t,r,i={},o=Object.keys(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||(i[t]=e[t]);return i}(e,n);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}function d(e){return function(e){if(Array.isArray(e))return u(e)}(e)||function(e){if("undefined"!==typeof Symbol&&null!=e[Symbol.iterator]||null!=e["@@iterator"])return Array.from(e)}(e)||function(e,n){if(!e)return;if("string"===typeof e)return u(e,n);var t=Object.prototype.toString.call(e).slice(8,-1);"Object"===t&&e.constructor&&(t=e.constructor.name);if("Map"===t||"Set"===t)return Array.from(t);if("Arguments"===t||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t))return u(e,n)}(e)||function(){throw new TypeError("Invalid attempt to spread non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}function f(e){var n=function(e,n){if("object"!==v(e)||null===e)return e;var t=e[Symbol.toPrimitive];if(void 0!==t){var r=t.call(e,n||"default");if("object"!==v(r))return r;throw new TypeError("@@toPrimitive must return a primitive value.")}return("string"===n?String:Number)(e)}(e,"string");return"symbol"===v(n)?n:String(n)}var v=function(e){return e&&"undefined"!==typeof Symbol&&e.constructor===Symbol?"symbol":typeof e};var p="input",m={boolean:!1,number:0,string:""},h={createInputOnChangeHandlerOptions:{},required:!1,valueType:"string"},g=(0,r.forwardRef)((function(e,n){var t=e.input,i=e.inputTestBatch,u=e.onBlurAppend,v=e.onFirstRender,g=e.onFocusAppend,y=e.onUnmount,b=e.required,x=void 0===b?h.required:b,j=e.valueKey,w=e.valueType,P=void 0===w?h.valueType:w,O=e.createInputOnChangeHandlerOptions,S=void 0===O?h.createInputOnChangeHandlerOptions:O,k=S.postSet,Z=S.valueKey,C=void 0===Z?j:Z,A=s(e.createInputOnChangeHandlerOptions,["postSet","valueKey"]),I=t.props,N=(0,r.useMemo)((function(){return null!==C&&void 0!==C?C:"checked"in I?"checked":"value"}),[I,C]),V=I.onBlur,H=I.onChange,R=I.onFocus,M=I[N],F=void 0===M?m[P]:M,T=s(I,["onBlur","onChange","onFocus",N].map(f)),E=(0,r.useState)(F),z=E[0],B=E[1],D=(0,r.useState)(!1),_=D[0],L=D[1],q=(0,r.useState)(!1),U=q[0],$=q[1],Q=(0,r.useCallback)((function(e){B(e)}),[]),J=(0,r.useMemo)((function(){var e;return i&&(i.isRequired=x,e=(0,l.LT)(a({},p,i))),e}),[i,x]),G=(0,r.useMemo)((function(){return null!==V&&void 0!==V?V:J&&function(){for(var e=arguments.length,n=new Array(e),t=0;t<e;t++)n[t]=arguments[t];var r,i=n[0],o=i.target.value,l=J({inputs:a({},p,{value:o})});$(l),null===u||void 0===u||(r=u).call.apply(r,[null].concat(d(n)))}}),[V,u,J]),K=(0,r.useMemo)((function(){return o(c({postSet:function(){for(var e=arguments.length,n=new Array(e),t=0;t<e;t++)n[t]=arguments[t];var r,i;L(!0),null===H||void 0===H||(r=H).call.apply(r,[null].concat(d(n))),null===k||void 0===k||(i=k).call.apply(i,[null].concat(d(n)))},set:Q,setType:P,valueKey:N},A))}),[H,k,A,Q,N,P]),W=(0,r.useMemo)((function(){return null!==R&&void 0!==R?R:i&&function(){for(var e=arguments.length,n=new Array(e),t=0;t<e;t++)n[t]=arguments[t];var r,o,l;null===(o=i.defaults)||void 0===o||null===(l=o.onSuccess)||void 0===l||l.call(null,{append:{}}),null===g||void 0===g||(r=g).call.apply(r,[null].concat(d(n)))}}),[R,i,g]);return(0,r.useEffect)((function(){var e,n=null!==(e=null===J||void 0===J?void 0:J.call(null,{inputs:a({},p,{value:z}),isIgnoreOnCallbacks:!0}))&&void 0!==e&&e;return null===v||void 0===v||v.call(null,{isValid:n}),y}),[]),(0,r.useImperativeHandle)(n,(function(){return{getIsChangedByUser:function(){return _},getValue:function(){return z},isValid:function(){return U},setValue:Q}}),[z,_,U,Q]),(0,r.cloneElement)(t,c({},T,a({onBlur:G,onChange:K,onFocus:W,required:x},N,z)))}));g.defaultProps=h,g.displayName="InputWithRef";var y=g},7869:function(e,n,t){"use strict";var r=t(5893),i=t(7294),o=t(8187);function l(e,n){(null==n||n>e.length)&&(n=e.length);for(var t=0,r=new Array(n);t<n;t++)r[t]=e[t];return r}function u(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function a(e,n){if(null==e)return{};var t,r,i=function(e,n){if(null==e)return{};var t,r,i={},o=Object.keys(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||(i[t]=e[t]);return i}(e,n);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}function c(e,n){return function(e){if(Array.isArray(e))return e}(e)||function(e,n){var t=null==e?null:"undefined"!==typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(null!=t){var r,i,o=[],l=!0,u=!1;try{for(t=t.call(e);!(l=(r=t.next()).done)&&(o.push(r.value),!n||o.length!==n);l=!0);}catch(a){u=!0,i=a}finally{try{l||null==t.return||t.return()}finally{if(u)throw i}}return o}}(e,n)||function(e,n){if(!e)return;if("string"===typeof e)return l(e,n);var t=Object.prototype.toString.call(e).slice(8,-1);"Object"===t&&e.constructor&&(t=e.constructor.name);if("Map"===t||"Set"===t)return Array.from(t);if("Arguments"===t||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t))return l(e,n)}(e,n)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}function s(e){var n=function(e,n){if("object"!==d(e)||null===e)return e;var t=e[Symbol.toPrimitive];if(void 0!==t){var r=t.call(e,n||"default");if("object"!==d(r))return r;throw new TypeError("@@toPrimitive must return a primitive value.")}return("string"===n?String:Number)(e)}(e,"string");return"symbol"===d(n)?n:String(n)}var d=function(e){return e&&"undefined"!==typeof Symbol&&e.constructor===Symbol?"symbol":typeof e};var f={count:0,defaultMessageType:"info",messages:void 0,onSet:void 0,usePlaceholder:!0},v=(0,i.forwardRef)((function(e,n){var t=e.count,l=void 0===t?f.count:t,d=e.defaultMessageType,v=void 0===d?f.defaultMessageType:d,p=e.messages,m=e.onSet,h=e.usePlaceholder,g=void 0===h?f.usePlaceholder:h,y=(0,i.useState)({}),b=y[0],x=y[1],j=(0,i.useMemo)((function(){return function(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{},r=Object.keys(t);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(t).filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable})))),r.forEach((function(n){u(e,n,t[n])}))}return e}({},p,b)}),[p,b]),w=(0,i.useCallback)((function(e){return void 0!==j[e]}),[j]),P=(0,i.useCallback)((function(e,n){var t=0;x((function(r){r[e];var i=a(r,[e].map(s));return n&&(i[e]=n),t=Object.keys(i).length,i})),null===m||void 0===m||m.call(null,t)}),[m]),O=(0,i.useCallback)((function(e,n){var t=0,r=n?function(e,r){e[r]=n,t+=1}:void 0;x((function(n){var i={};return Object.keys(n).forEach((function(o){e.test(o)?null===r||void 0===r||r.call(null,i,o):(i[o]=n[o],t+=1)})),i})),null===m||void 0===m||m.call(null,t)}),[m]),S=(0,i.useMemo)((function(){var e=Object.entries(j),n=l>0,t=n?l:e.length,i=[];if(e.every((function(e){var n=c(e,2),l=n[0],u=n[1],a=u.children,s=u.type,d=void 0===s?v:s;return i.push((0,r.jsx)(o.Z,{type:d,children:a},"message-".concat(l))),i.length<t})),g&&n&&0===i.length)for(var u=l-i.length,a=0;a<u;a+=1)i.push((0,r.jsx)(o.Z,{sx:{visibility:"hidden"},text:"Placeholder"},"message-placeholder-".concat(a)));return i}),[l,v,g,j]);return(0,i.useImperativeHandle)(n,(function(){return{exists:w,setMessage:P,setMessageRe:O}}),[w,P,O]),(0,r.jsx)(r.Fragment,{children:S})}));v.defaultProps=f,v.displayName="MessageGroup",n.Z=v},3675:function(e,n){"use strict";var t={boolean:function(e){return Boolean(e)},number:function(e){return parseInt(String(e),10)||0},string:function(e){return String(e)}};n.Z=t},8616:function(e,n,t){"use strict";t.r(n),t.d(n,{default:function(){return ue}});var r=t(5893),i=t(7357),o=t(1113),l=t(6886),u=t(1163),a=t(7294),c=t(2029),s=t(7169),d=t(4390),f=t(157),v=t(4825),p=t(4690),m=t(8128),h=t(4188),g=t(1250),y=t(4069),b=t(8187),x=t(7869),j=t(6284),w=function(e){var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},t=n.fillString,r=void 0===t?"0":t,i=n.maxLength,o=void 0===i?2:i,l=n.which,u=void 0===l?"Start":l;return String(e)["pad".concat(u)](o,r)};function P(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function O(e,n){if(null==e)return{};var t,r,i=function(e,n){if(null==e)return{};var t,r,i={},o=Object.keys(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||(i[t]=e[t]);return i}(e,n);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}var S={show:!0},k=function(e){var n=e.onClick,t=e.show,i=void 0===t?S.show:t,o=O(e,["onClick","show"]);return i?(0,r.jsx)(v.Z,function(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{},r=Object.keys(t);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(t).filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable})))),r.forEach((function(n){P(e,n,t[n])}))}return e}({onClick:n,tabIndex:-1},o,{children:"Suggest"})):(0,r.jsx)(r.Fragment,{})};k.defaultProps=S;var Z=k,C=t(7987),A=t(7750);function I(e,n){(null==n||n>e.length)&&(n=e.length);for(var t=0,r=new Array(n);t<n;t++)r[t]=e[t];return r}function N(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function V(e,n){return function(e){if(Array.isArray(e))return e}(e)||function(e,n){var t=null==e?null:"undefined"!==typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(null!=t){var r,i,o=[],l=!0,u=!1;try{for(t=t.call(e);!(l=(r=t.next()).done)&&(o.push(r.value),!n||o.length!==n);l=!0);}catch(a){u=!0,i=a}finally{try{l||null==t.return||t.return()}finally{if(u)throw i}}return o}}(e,n)||R(e,n)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}function H(e){return function(e){if(Array.isArray(e))return I(e)}(e)||function(e){if("undefined"!==typeof Symbol&&null!=e[Symbol.iterator]||null!=e["@@iterator"])return Array.from(e)}(e)||R(e)||function(){throw new TypeError("Invalid attempt to spread non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}function R(e,n){if(e){if("string"===typeof e)return I(e,n);var t=Object.prototype.toString.call(e).slice(8,-1);return"Object"===t&&e.constructor&&(t=e.constructor.name),"Map"===t||"Set"===t?Array.from(t):"Arguments"===t||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t)?I(e,n):void 0}}var M="adminPassword",F="confirmAdminPassword",T="domainName",E="hostName",z="hostNumber",B="organizationName",D="organizationPrefix",_={0:function(){return""},1:function(e){return V(e,1)[0].substring(0,1).toLocaleLowerCase()},2:function(e){return e.map((function(e){return e.substring(0,1).toLocaleLowerCase()})).join("")}},L=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:"",n=e.split(/\s/).filter((function(e){return!/and|of/.test(e)})).slice(0,5),t=n.length>1?2:n.length;return _[t](n)},q=function(e){var n=e.organizationPrefix,t=e.hostNumber,r=e.domainName;return[n,t,r].every((function(e){return Boolean(e)}))?"".concat(n,"-striker").concat(w(t),".").concat(r):""},U=(0,a.forwardRef)((function(e,n){var t,i,o,u,c=e.expectHostDetail,s=void 0!==c&&c,d=e.hostDetail,f=e.onHostNumberBlurAppend,v=e.toggleSubmitDisabled,w=(0,a.useState)(),P=w[0],O=w[1],S=(0,a.useState)(!1),k=S[0],I=S[1],R=(0,a.useState)(!1),_=R[0],U=R[1],$=(0,a.useState)(!0),Q=$[0],J=$[1],G=(0,a.useState)(!0),K=G[0],W=G[1],X=(0,a.useRef)(!0),Y=(0,a.useRef)({}),ee=(0,a.useRef)({}),ne=(0,a.useRef)({}),te=(0,a.useRef)({}),re=(0,a.useRef)({}),ie=(0,a.useRef)({}),oe=(0,a.useRef)({}),le=(0,a.useRef)({}),ue=(0,a.useCallback)((function(e){var n;return null===(n=le.current.setMessage)||void 0===n?void 0:n.call(null,D,e)}),[]),ae=(0,a.useCallback)((function(e){var n;return null===(n=le.current.setMessage)||void 0===n?void 0:n.call(null,z,e)}),[]),ce=(0,a.useCallback)((function(e){var n;return null===(n=le.current.setMessage)||void 0===n?void 0:n.call(null,T,e)}),[]),se=(0,a.useCallback)((function(e){var n;return null===(n=le.current.setMessage)||void 0===n?void 0:n.call(null,E,e)}),[]),de=(0,a.useCallback)((function(e){var n;return null===(n=le.current.setMessage)||void 0===n?void 0:n.call(null,M,e)}),[]),fe=(0,a.useCallback)((function(e){var n;return null===(n=le.current.setMessage)||void 0===n?void 0:n.call(null,F,e)}),[]),ve=(0,a.useMemo)((function(){var e;return N(e={},M,{defaults:{getValue:function(){var e;return null===(e=Y.current.getValue)||void 0===e?void 0:e.call(null)},onSuccess:function(){de(void 0)}},tests:[{onFailure:function(){de({children:(0,r.jsxs)(r.Fragment,{children:["Admin password cannot contain single-quote (",(0,r.jsx)(A.Q0,{text:"'"}),"), double-quote (",(0,r.jsx)(A.Q0,{text:'"'}),"), slash (",(0,r.jsx)(A.Q0,{text:"/"}),"), backslash (",(0,r.jsx)(A.Q0,{text:"\\"}),"), angle brackets (",(0,r.jsx)(A.Q0,{text:"<>"}),"), curly brackets (",(0,r.jsx)(A.Q0,{text:"{}"}),")."]})})},test:function(e){var n=e.value;return!/['"/\\><}{]/g.test(n)}},{test:C.HJ}]}),N(e,F,{defaults:{getValue:function(){var e,n;return null===(e=ee.current)||void 0===e||null===(n=e.getValue)||void 0===n?void 0:n.call(null)},onSuccess:function(){fe(void 0)}},tests:[{onFailure:function(){fe({children:"Confirmation doesn't match admin password."})},test:function(e){var n;return e.value===(null===(n=Y.current.getValue)||void 0===n?void 0:n.call(null))}},{test:C.HJ}]}),N(e,T,{defaults:{compare:[!K],getValue:function(){var e;return null===(e=re.current.getValue)||void 0===e?void 0:e.call(null)},onSuccess:function(){ce(void 0)}},tests:[{onFailure:function(){ce({children:(0,r.jsxs)(r.Fragment,{children:["Domain name can only contain lowercase alphanumeric, hyphen (",(0,r.jsx)(A.Q0,{text:"-"}),"), and dot (",(0,r.jsx)(A.Q0,{text:"."}),") characters."]})})},test:function(e){var n=e.compare,t=e.value;return n[0]||g.FZ.test(t)}},{test:C.HJ}]}),N(e,E,{defaults:{compare:[!K],getValue:function(){var e;return null===(e=oe.current.getValue)||void 0===e?void 0:e.call(null)},onSuccess:function(){se(void 0)}},tests:[{onFailure:function(){se({children:(0,r.jsxs)(r.Fragment,{children:["Host name can only contain lowercase alphanumeric, hyphen (",(0,r.jsx)(A.Q0,{text:"-"}),"), and dot (",(0,r.jsx)(A.Q0,{text:"."}),") characters."]})})},test:function(e){var n=e.compare,t=e.value;return n[0]||g.FZ.test(t)}},{test:C.HJ}]}),N(e,z,{defaults:{getValue:function(){var e;return null===(e=ie.current.getValue)||void 0===e?void 0:e.call(null)},onSuccess:function(){ae(void 0)}},tests:[{onFailure:function(){ae({children:"Striker number can only contain digits."})},test:function(e){var n=e.value;return/^\d+$/.test(n)}},{test:C.HJ}]}),N(e,B,{defaults:{getValue:function(){var e;return null===(e=ne.current.getValue)||void 0===e?void 0:e.call(null)}},tests:[{test:C.HJ}]}),N(e,D,{defaults:{getValue:function(){var e;return null===(e=te.current.getValue)||void 0===e?void 0:e.call(null)},max:5,min:1,onSuccess:function(){ue(void 0)}},tests:[{onFailure:function(e){var n=e.max,t=e.min;ue({children:"Organization prefix must be ".concat(t," to ").concat(n," lowercase alphanumeric characters.")})},test:function(e){var n=e.max,t=e.min,r=e.value;return RegExp("^[a-z0-9]{".concat(t,",").concat(n,"}$")).test(r)}}]}),e}),[K,de,fe,ce,se,ae,ue]),pe=(0,a.useMemo)((function(){return(0,C.LT)(ve)}),[ve]),me=(0,a.useCallback)((function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},n=e.excludeTestIds,t=void 0===n?[]:n,r=e.inputs,i=e.isContinueOnFailure,o=e.isExcludeConfirmAdminPassword,l=void 0===o?!Q:o;l&&t.push(F),null===v||void 0===v||v.call(null,pe({excludeTestIds:t,inputs:r,isContinueOnFailure:i,isIgnoreOnCallbacks:!0,isTestAll:!0}))}),[Q,pe,v]),he=(0,a.useCallback)((function(){var e,n=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},r=n.organizationName,i=void 0===r?null===(t=ne.current.getValue)||void 0===t?void 0:t.call(null):r,o=L(i);return null===(e=te.current.setValue)||void 0===e||e.call(null,o),me({inputs:N({},D,{isIgnoreOnCallbacks:!1,value:o}),isContinueOnFailure:!0}),o}),[me]),ge=(0,a.useCallback)((function(){var e,n=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},t=n.organizationPrefix,r=void 0===t?null===(i=te.current.getValue)||void 0===i?void 0:i.call(null):t,l=n.hostNumber,a=void 0===l?null===(o=ie.current.getValue)||void 0===o?void 0:o.call(null):l,c=n.domainName,s=void 0===c?null===(u=re.current.getValue)||void 0===u?void 0:u.call(null):c,d=q({organizationPrefix:r,hostNumber:a,domainName:s});return null===(e=oe.current.setValue)||void 0===e||e.call(null,d),me({inputs:N({},E,{isIgnoreOnCallbacks:!1,value:d}),isContinueOnFailure:!0}),d}),[me]),ye=(0,a.useCallback)((function(){var e;return Boolean(null===(e=ne.current.getValue)||void 0===e?void 0:e.call(null))}),[]),be=(0,a.useCallback)((function(){var e,n,t;return[null===(e=te.current.getValue)||void 0===e?void 0:e.call(null),null===(n=ie.current.getValue)||void 0===n?void 0:n.call(null),null===(t=re.current.getValue)||void 0===t?void 0:t.call(null)].every((function(e){return Boolean(e)}))}),[]),xe=(0,a.useCallback)((function(){var e;(null===(e=te.current.getIsChangedByUser)||void 0===e?void 0:e.call(null))?I(ye()):he()}),[ye,he]),je=(0,a.useCallback)((function(){var e;(null===(e=oe.current.getIsChangedByUser)||void 0===e?void 0:e.call(null))?U(be()):ge()}),[be,ge]),we=(0,a.useCallback)((function(){var e,n=he();(null===(e=oe.current.getIsChangedByUser)||void 0===e?void 0:e.call(null))||ge({organizationPrefix:n})}),[ge,he]),Pe=(0,a.useCallback)((function(){ge()}),[ge]),Oe=(0,a.useCallback)((function(e){return function(n){return n===e?void 0:e}}),[]),Se=(0,a.useMemo)((function(){return(0,r.jsx)(m.Z,{checked:K,onChange:function(e,n){var t;W(n),me({inputs:(t={},N(t,T,{compare:[!n],isIgnoreOnCallbacks:!1}),N(t,E,{compare:[!n],isIgnoreOnCallbacks:!1}),t),isContinueOnFailure:!0})},sx:{padding:".2em"}})}),[K,me]);return(0,a.useEffect)((function(){if([s,d,X.current,re.current,oe.current,ie.current,ne.current,te.current].every((function(e){return Boolean(e)}))){var e,n,t,r,i;X.current=!1;var o=d.domain,l=d.hostName,u=d.organization,a=d.prefix,c=d.sequence;null===(e=re.current.setValue)||void 0===e||e.call(null,o),null===(n=oe.current.setValue)||void 0===n||n.call(null,l),null===(t=ie.current.setValue)||void 0===t||t.call(null,c),null===(r=ne.current.setValue)||void 0===r||r.call(null,u),null===(i=te.current.setValue)||void 0===i||i.call(null,a),me()}}),[s,d,me]),(0,a.useImperativeHandle)(n,(function(){return{get:function(){var e,n,t,r,i,o;return{adminPassword:null===(e=Y.current.getValue)||void 0===e?void 0:e.call(null),organizationName:null===(n=ne.current.getValue)||void 0===n?void 0:n.call(null),organizationPrefix:null===(t=te.current.getValue)||void 0===t?void 0:t.call(null),domainName:null===(r=re.current.getValue)||void 0===r?void 0:r.call(null),hostNumber:null===(i=ie.current.getValue)||void 0===i?void 0:i.call(null),hostName:null===(o=oe.current.getValue)||void 0===o?void 0:o.call(null)}}}})),(0,r.jsxs)(p.Z,{children:[(0,r.jsxs)(l.ZP,{columns:{xs:1,sm:2,md:3},container:!0,spacing:"1em",children:[(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsxs)(p.Z,{children:[(0,r.jsx)(y.Z,{input:(0,r.jsx)(j.Z,{id:"striker-init-general-organization-name",inputProps:{onBlur:xe},inputLabelProps:{isNotifyRequired:!0},label:"Organization name",onChange:function(){me()},onHelp:function(){O(Oe("Name of the organization that maintains this Anvil! system. You can enter anything that makes sense to you."))}}),ref:ne}),(0,r.jsxs)(p.Z,{row:!0,sx:{"& > :first-child":{flexGrow:1}},children:[(0,r.jsx)(y.Z,{input:(0,r.jsx)(j.Z,{id:"striker-init-general-organization-prefix",inputProps:{endAdornment:(0,r.jsx)(Z,{show:k,onClick:we}),inputProps:{maxLength:5,sx:{minWidth:"2.5em"}},onBlur:function(e){for(var n=arguments.length,t=new Array(n>1?n-1:0),r=1;r<n;r++)t[r-1]=arguments[r];var i=e.target.value;pe({inputs:N({},D,{value:i})}),je.apply(void 0,[e].concat(H(t)))}},inputLabelProps:{isNotifyRequired:!0},label:"Prefix",onChange:function(e){var n=e.target.value;me({inputs:N({},D,{value:n})}),ue(),I(ye())},onHelp:function(){O(Oe("Alphanumberic short-form of the organization name. It's used as the prefix for host names."))}}),ref:te}),(0,r.jsx)(y.Z,{input:(0,r.jsx)(j.Z,{id:"striker-init-general-host-number",inputProps:{inputProps:{maxLength:2,sx:{minWidth:"2em"}},onBlur:function(){for(var e=arguments.length,n=new Array(e),t=0;t<e;t++)n[t]=arguments[t];var r,i=V(n,1),o=i[0],l=o.target.value;pe({inputs:N({},z,{value:l})}),je.apply(void 0,H(n)),null===f||void 0===f||(r=f).call.apply(r,[null].concat(H(n)))}},inputLabelProps:{isNotifyRequired:!0},label:"Striker #",onChange:function(e){var n=e.target.value;me({inputs:N({},z,{value:n})}),ae()},onHelp:function(){O(Oe("Number or count of this striker; this should be '1' for the first striker, '2' for the second striker, and such."))}}),ref:ie,valueType:"number"})]})]})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsxs)(p.Z,{children:[(0,r.jsx)(y.Z,{input:(0,r.jsx)(j.Z,{id:"striker-init-general-domain-name",inputProps:{onBlur:function(e){for(var n=arguments.length,t=new Array(n>1?n-1:0),r=1;r<n;r++)t[r-1]=arguments[r];var i=e.target.value;pe({inputs:N({},T,{value:i})}),je.apply(void 0,[e].concat(H(t)))}},inputLabelProps:{isNotifyRequired:!0},label:"Domain name",onChange:function(e){var n=e.target.value;me({inputs:N({},T,{value:n})}),ce()},onHelp:function(){O(Oe("Domain name for this striker. It's also the default domain used when creating new install manifests."))}}),ref:re}),(0,r.jsx)(y.Z,{input:(0,r.jsx)(j.Z,{id:"striker-init-general-host-name",inputProps:{endAdornment:(0,r.jsx)(Z,{show:_,onClick:Pe}),onBlur:function(e){var n=e.target.value;pe({inputs:N({},E,{value:n})})}},inputLabelProps:{isNotifyRequired:!0},label:"Host name",onChange:function(e){var n=e.target.value;me({inputs:N({},E,{value:n})}),se(),U(be())},onHelp:function(){O(Oe("Host name for this striker. It's usually a good idea to use the auto-generated value."))}}),ref:oe})]})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,sm:2,md:1,children:(0,r.jsxs)(l.ZP,{columns:{xs:1,sm:2,md:1},container:!0,spacing:"1em",sx:{"& > * > *":{width:"100%"}},children:[(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(y.Z,{input:(0,r.jsx)(j.Z,{id:"striker-init-general-admin-password",inputProps:{inputProps:{type:h.Z.password},onBlur:function(e){var n=e.target.value;pe({inputs:N({},M,{value:n})})},onPasswordVisibilityAppend:function(e){var n=e===h.Z.password;me({isExcludeConfirmAdminPassword:!n}),J(n),fe()}},inputLabelProps:{isNotifyRequired:!0},label:"Admin password",onChange:function(e){var n=e.target.value;me({inputs:N({},M,{value:n})}),de()},onHelp:function(){O(Oe("Password use to login to this Striker and connect to its database. Don't provide an used password here because it'll be stored as plaintext."))}}),ref:Y})}),Q&&(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(y.Z,{input:(0,r.jsx)(j.Z,{id:"striker-init-general-confirm-admin-password",inputProps:{inputProps:{type:h.Z.password},onBlur:function(e){var n=e.target.value;pe({inputs:N({},F,{value:n})})}},inputLabelProps:{isNotifyRequired:Q},label:"Confirm password",onChange:function(e){var n=e.target.value;me({inputs:N({},F,{value:n})}),fe()}}),ref:ee})})]})})]}),(0,r.jsx)(x.Z,{count:1,defaultMessageType:"warning",ref:le}),(0,r.jsx)(b.Z,{children:(0,r.jsxs)(p.Z,{row:!0,sx:{"& > :last-child":{flexGrow:1}},children:[Se,(0,r.jsx)(A.Ac,{inverted:!0,children:K?"Uncheck to skip domain and host name pattern validation.":"Check to re-enable domain and host name pattern validation."})]})}),P&&(0,r.jsx)(b.Z,{onClose:function(){O(void 0)},children:P})]})}));U.defaultProps={expectHostDetail:!1,hostDetail:void 0,onHostNumberBlurAppend:void 0,toggleSubmitDisabled:void 0},U.displayName="GeneralInitForm";var $=U,Q=t(1770),J=t(1706),G=t(3377),K=t(2444),W=t(5741),X=t(4596),Y=t(3679),ee=t(2152),ne=t(2749);function te(e,n){(null==n||n>e.length)&&(n=e.length);for(var t=0,r=new Array(n);t<n;t++)r[t]=e[t];return r}function re(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function ie(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{},r=Object.keys(t);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(t).filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable})))),r.forEach((function(n){re(e,n,t[n])}))}return e}function oe(e,n){return function(e){if(Array.isArray(e))return e}(e)||function(e,n){var t=null==e?null:"undefined"!==typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(null!=t){var r,i,o=[],l=!0,u=!1;try{for(t=t.call(e);!(l=(r=t.next()).done)&&(o.push(r.value),!n||o.length!==n);l=!0);}catch(a){u=!0,i=a}finally{try{l||null==t.return||t.return()}finally{if(u)throw i}}return o}}(e,n)||function(e,n){if(!e)return;if("string"===typeof e)return te(e,n);var t=Object.prototype.toString.call(e).slice(8,-1);"Object"===t&&e.constructor&&(t=e.constructor.name);if("Map"===t||"Set"===t)return Array.from(t);if("Arguments"===t||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t))return te(e,n)}(e,n)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}var le=function(){var e,n=(0,u.useRouter)(),t=n.isReady,i=n.query.re,m=(0,a.useState)(),h=m[0],g=m[1],y=(0,a.useState)(),x=y[0],j=y[1],w=(0,a.useState)(!1),P=w[0],O=w[1],S=(0,a.useState)(!0),k=S[0],Z=S[1],C=(0,a.useState)(!1),I=C[0],N=C[1],V=(0,a.useState)(!1),H=V[0],R=V[1],M=(0,a.useState)(!1),F=M[0],T=M[1],E=(0,a.useState)(),z=E[0],B=E[1],D=oe((0,ne.Z)(void 0),2),_=D[0],L=D[1],q=(0,a.useRef)(!0),U=(0,a.useRef)({}),te=(0,a.useRef)({}),re=(0,a.useRef)({}),le=(0,a.useRef)({}),ue=(0,a.useMemo)((function(){return Boolean(i)}),[i]),ae=(0,a.useMemo)((function(){return F?(0,r.jsx)(ee.Z,{}):(0,r.jsx)(p.Z,{row:!0,sx:{flexDirection:"row-reverse"},children:(0,r.jsx)(v.Z,{disabled:k,onClick:function(){var e,n,t,r;j(ie({},null!==(t=null===(e=U.current.get)||void 0===e?void 0:e.call(null))&&void 0!==t?t:{},null!==(r=null===(n=te.current.get)||void 0===n?void 0:n.call(null))&&void 0!==r?r:{networks:[]})),O(!0)},children:"Initialize"})})}),[k,F]),ce=(0,a.useMemo)((function(){var e,n="Loading...";t&&(n=ue?"Reconfigure ".concat(null!==(e=null===_||void 0===_?void 0:_.shortHostName)&&void 0!==e?e:"striker"):"Initialize striker");return n}),[null===_||void 0===_?void 0:_.shortHostName,t,ue]),se=(0,a.useCallback)((function(){for(var e=arguments.length,n=new Array(e),t=0;t<e;t++)n[t]=arguments[t];Z(!n.every((function(e){return e})))}),[]);return(0,a.useEffect)((function(){t&&ue&&q.current&&(q.current=!1,d.Z.get("/host/local").then((function(e){var n=e.data;L(n)})).catch((function(e){var n=(0,Q.Z)(e);n.children=(0,r.jsxs)(r.Fragment,{children:["Failed to get host detail data. ",n.children]}),g(n)})))}),[t,ue,L]),(0,r.jsxs)(r.Fragment,{children:[(0,r.jsxs)(Y.s_,{children:[(0,r.jsxs)(Y.V9,{children:[(0,r.jsx)(A.z,{children:ce}),(0,r.jsx)(J.Z,{onClick:function(e){var n,t,r=e.currentTarget;null===(n=le.current.setAnchor)||void 0===n||n.call(null,r),null===(t=le.current.setOpen)||void 0===t||t.call(null,!0)},variant:"normal",children:(0,r.jsx)(G.Z,{icon:o.Z,ref:re})})]}),(0,r.jsxs)(p.Z,{children:[(0,r.jsx)($,{expectHostDetail:ue,hostDetail:_,onHostNumberBlurAppend:function(e){var n=e.target.value;B(n)},ref:U,toggleSubmitDisabled:function(e){e!==I&&(N(e),se(e,H))}}),(0,r.jsx)(X.Z,{expectHostDetail:ue,hostDetail:_,hostSequence:z,ref:te,toggleSubmitDisabled:function(e){e!==H&&(R(e),se(I,e))}}),h&&(0,r.jsx)(b.Z,ie({},h,{onClose:function(){return g(void 0)}})),ae]})]}),(0,r.jsx)(f.Z,{actionProceedText:"Initialize",content:(0,r.jsxs)(l.ZP,{container:!0,spacing:".6em",columns:{xs:2},children:[(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.Ac,{children:"Organization name"})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.$_,{children:null===x||void 0===x?void 0:x.organizationName})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.Ac,{children:"Organization prefix"})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.$_,{children:null===x||void 0===x?void 0:x.organizationPrefix})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.Ac,{children:"Striker number"})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.$_,{children:null===x||void 0===x?void 0:x.hostNumber})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.Ac,{children:"Domain name"})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.$_,{children:null===x||void 0===x?void 0:x.domainName})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.Ac,{children:"Host name"})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.$_,{children:null===x||void 0===x?void 0:x.hostName})}),(0,r.jsx)(l.ZP,{item:!0,sx:{marginTop:"1.4em"},xs:2,children:(0,r.jsx)(A.Ac,{children:"Networks"})}),null===x||void 0===x?void 0:x.networks.map((function(e){var n=e.inputUUID,t=e.interfaces,i=e.ipAddress,o=e.name,u=e.subnetMask,a=e.type,c=e.typeCount;return(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsxs)(l.ZP,{container:!0,spacing:".6em",columns:{xs:2},children:[(0,r.jsx)(l.ZP,{item:!0,xs:2,children:(0,r.jsxs)(A.Ac,{children:[o," (",(0,r.jsx)(A.Q0,{children:"".concat(a.toUpperCase()).concat(c)}),")"]})}),t.map((function(e,t){var i="network-confirm-".concat(n,"-interface").concat(t),o="none";if(e){var u=e.networkInterfaceName,a=e.networkInterfaceUUID;i="".concat(i,"-").concat(a),o=u}return(0,r.jsxs)(l.ZP,{container:!0,item:!0,children:[(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.Ac,{children:"Link ".concat(t+1)})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.$_,{children:o})})]},i)})),(0,r.jsx)(l.ZP,{item:!0,xs:2,children:(0,r.jsx)(A.$_,{children:"".concat(i,"/").concat(u)})})]})},"network-confirm-".concat(n))})),(0,r.jsx)(l.ZP,{item:!0,sx:{marginBottom:"1.4em"},xs:2}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.Ac,{children:"Gateway"})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.$_,{children:null===x||void 0===x?void 0:x.gateway})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.Ac,{children:"Gateway network"})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.$_,{children:null===x||void 0===x||null===(e=x.gatewayInterface)||void 0===e?void 0:e.toUpperCase()})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.Ac,{children:"Domain name server(s)"})}),(0,r.jsx)(l.ZP,{item:!0,xs:1,children:(0,r.jsx)(A.$_,{children:null===x||void 0===x?void 0:x.dns})})]}),dialogProps:{open:P},onCancelAppend:function(){O(!1)},onProceedAppend:function(){g(void 0),T(!0),O(!1),d.Z.put("/init",x).then((function(){T(!1),g({children:(0,r.jsxs)(r.Fragment,{children:["Successfully registered the configuration job! You can check the progress at the top right icon. Once the job completes, you can access the"," ",(0,r.jsx)(W.Z,{href:"/login",sx:{color:s.E5,display:"inline-flex"},children:"login page"}),"."]}),type:"info"})})).catch((function(e){var n=(0,Q.Z)(e);g(n),T(!1)}))},titleText:"Confirm striker initialization"}),(0,r.jsx)(K.Z,{getJobUrl:function(e){return"".concat(c.Z,"/init/job?start=").concat(e)},onFetchSuccessAppend:function(e){var n;null===(n=re.current.indicate)||void 0===n||n.call(null,Object.keys(e).length>0)},ref:le})]})},ue=function(){return(0,r.jsx)(i.Z,{sx:{display:"flex",flexDirection:"column"},children:(0,r.jsx)(le,{})})}}},function(e){e.O(0,[382,438,182,434,644,676,62,195,987,157,86,774,888,179],(function(){return n=593,e(e.s=n);var n}));var n=e.O();_N_E=n}]);