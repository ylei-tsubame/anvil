(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[705],{3457:function(e,r,n){"use strict";n.d(r,{Z:function(){return y}});var t=n(3366),o=n(7462),l=n(7294),i=n(6010),a=n(7192),s=n(1496),u=n(3616),c=n(8979);function d(e){return(0,c.Z)("MuiFormGroup",e)}(0,n(6087).Z)("MuiFormGroup",["root","row","error"]);var p=n(4423),f=n(5704),h=n(5893);const v=["className","row"],m=(0,s.ZP)("div",{name:"MuiFormGroup",slot:"Root",overridesResolver:(e,r)=>{const{ownerState:n}=e;return[r.root,n.row&&r.row]}})((({ownerState:e})=>(0,o.Z)({display:"flex",flexDirection:"column",flexWrap:"wrap"},e.row&&{flexDirection:"row"})));var y=l.forwardRef((function(e,r){const n=(0,u.Z)({props:e,name:"MuiFormGroup"}),{className:l,row:s=!1}=n,c=(0,t.Z)(n,v),y=(0,p.Z)(),b=(0,f.Z)({props:n,muiFormControl:y,states:["error"]}),x=(0,o.Z)({},n,{row:s,error:b.error}),g=(e=>{const{classes:r,row:n,error:t}=e,o={root:["root",n&&"row",t&&"error"]};return(0,a.Z)(o,d,r)})(x);return(0,h.jsx)(m,(0,o.Z)({className:(0,i.Z)(g.root,l),ownerState:x,ref:r},c))}))},3187:function(e,r,n){(window.__NEXT_P=window.__NEXT_P||[]).push(["/prepare-host",function(){return n(9093)}])},9093:function(e,r,n){"use strict";n.r(r),n.d(r,{default:function(){return Le}});var t=n(5893),o=n(9008),l=n(5716),i=n(7504),a=n(5697),s=n(2186),u=n(7357),c=n(4799),d=n(7294),p=n(7169),f=n(4188),h=n(4390),v=n(1770),m=n(9914),y=n(157),b=n(4825),x=n(4690),g=n(9434),j=n(7869),w=n(6284),Z=n(2152);function P(e,r){(null==r||r>e.length)&&(r=e.length);for(var n=0,t=new Array(r);n<r;n++)t[n]=e[n];return t}function S(e,r,n){return r in e?Object.defineProperty(e,r,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[r]=n,e}function C(e){for(var r=1;r<arguments.length;r++){var n=null!=arguments[r]?arguments[r]:{},t=Object.keys(n);"function"===typeof Object.getOwnPropertySymbols&&(t=t.concat(Object.getOwnPropertySymbols(n).filter((function(e){return Object.getOwnPropertyDescriptor(n,e).enumerable})))),t.forEach((function(r){S(e,r,n[r])}))}return e}function O(e,r){if(null==e)return{};var n,t,o=function(e,r){if(null==e)return{};var n,t,o={},l=Object.keys(e);for(t=0;t<l.length;t++)n=l[t],r.indexOf(n)>=0||(o[n]=e[n]);return o}(e,r);if(Object.getOwnPropertySymbols){var l=Object.getOwnPropertySymbols(e);for(t=0;t<l.length;t++)n=l[t],r.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}function k(e){return function(e){if(Array.isArray(e))return P(e)}(e)||function(e){if("undefined"!==typeof Symbol&&null!=e[Symbol.iterator]||null!=e["@@iterator"])return Array.from(e)}(e)||function(e,r){if(!e)return;if("string"===typeof e)return P(e,r);var n=Object.prototype.toString.call(e).slice(8,-1);"Object"===n&&e.constructor&&(n=e.constructor.name);if("Map"===n||"Set"===n)return Array.from(n);if("Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n))return P(e,r)}(e)||function(){throw new TypeError("Invalid attempt to spread non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}var A={width:"100%"},I="identifier",M="passphrase",R="accessError",V="identifierInputError",N="passphraseInputError",_=(0,d.forwardRef)((function(e,r){var n,o,l,a=e.allowSubmit,s=void 0===a||a,u=e.gridProps,c=void 0===u?{}:u,p=c.columns,h=void 0===p?{xs:1,sm:2}:p,v=(c.layout,c.spacing),y=void 0===v?"1em":v,P=e.identifierLabel,_=e.identifierOutlinedInputWithLabelProps,B=void 0===_?{}:_,E=B.formControlProps,F=void 0===E?{}:E,H=B.inputProps,T=e.identifierInputTestBatchBuilder,L=e.onIdentifierBlurAppend,U=e.onSubmit,z=e.onSubmitAppend,G=e.passphraseLabel,$=e.passphraseOutlinedInputWithLabelProps,D=void 0===$?{}:$,W=D.formControlProps,q=void 0===W?{}:W,K=D.inputProps,X=e.submitLabel,Y=O(e.gridProps,["columns","layout","spacing"]),J=O(e.identifierOutlinedInputWithLabelProps,["formControlProps","inputProps"]),Q=O(e.passphraseOutlinedInputWithLabelProps,["formControlProps","inputProps"]),ee=F.sx,re=O(F,["sx"]),ne=q.sx,te=O(q,["sx"]),oe=(0,d.useRef)({}),le=(0,d.useRef)({}),ie=(0,d.useRef)({}),ae=(0,d.useState)(!1),se=ae[0],ue=ae[1],ce=(0,d.useState)(!1),de=ce[0],pe=ce[1],fe=(0,d.useState)(!1),he=fe[0],ve=fe[1],me=(0,d.useCallback)((function(e){var r;null===(r=ie.current.setMessage)||void 0===r||r.call(null,R,e)}),[]),ye=(0,d.useCallback)((function(e){var r;null===(r=ie.current.setMessage)||void 0===r||r.call(null,V,e)}),[]),be=(0,d.useCallback)((function(e){var r;null===(r=ie.current.setMessage)||void 0===r||r.call(null,N,e)}),[]),xe=(0,d.useMemo)((function(){return s?void 0:"none"}),[s]),ge=(0,d.useMemo)((function(){return null!==(n=null===T||void 0===T?void 0:T.call(null,ye,oe.current))&&void 0!==n?n:(0,m.Gn)(P,(function(){ye()}),{getValue:oe.current.getValue},(function(e){ye({children:e,type:"warning"})}))}),[P,T,ye]),je=(0,d.useMemo)((function(){var e;return S(e={},I,ge),S(e,M,(0,m.Gn)(G,(function(){be()}),{getValue:le.current.getValue},(function(e){be({children:e,type:"warning"})}))),e}),[ge,G,be]),we=(0,d.useMemo)((function(){return null!==U&&void 0!==U?U:function(){for(var e=arguments.length,r=new Array(e),n=0;n<e;n++)r[n]=arguments[n];var t;me(),ve(!0),null===z||void 0===z||(t=z).call.apply(t,[null,oe.current,le.current,me,ve,ie.current].concat(k(r)))}}),[U,z,me]),Ze=(0,d.useMemo)((function(){return he?(0,t.jsx)(Z.Z,{mt:0}):(0,t.jsx)(x.Z,{row:!0,sx:{justifyContent:"flex-end"},children:(0,t.jsx)(b.Z,{disabled:!se||!de,onClick:we,children:X})})}),[se,de,he,we,X]),Pe=(0,d.useMemo)((function(){return s?{children:Ze,sm:2}:void 0}),[s,Ze]),Se=(0,d.useMemo)((function(){return(0,m.LT)(je)}),[je]);return(0,d.useImperativeHandle)(r,(function(){return{get:function(){var e,r;return{identifier:null!==(o=null===(e=oe.current.getValue)||void 0===e?void 0:e.call(null))&&void 0!==o?o:"",passphrase:null!==(l=null===(r=le.current.getValue)||void 0===r?void 0:r.call(null))&&void 0!==l?l:""}},messageGroup:C({},ie.current),setIsSubmitting:function(e){ve(e)}}})),(0,t.jsx)(i.Z,C({columns:h,layout:{"credential-identifier":{children:(0,t.jsx)(g.Z,{input:(0,t.jsx)(w.Z,C({formControlProps:C({},re,{sx:C({},A,ee)}),id:"credential-identifier-input",inputProps:C({onBlur:function(e){var r=e.target.value,n=Se({inputs:S({},I,{value:r})});ue(n),null===L||void 0===L||L.call(null,e)},onFocus:function(){ye()}},H),label:P},J)),ref:oe})},"credential-passphrase":{children:(0,t.jsx)(g.Z,{input:(0,t.jsx)(w.Z,C({formControlProps:C({},te,{sx:C({},A,ne)}),id:"credential-passphrase-input",inputProps:C({onBlur:function(e){var r=e.target.value,n=Se({inputs:S({},M,{value:r})});pe(n)},onFocus:function(){be()},type:f.Z.password},K),label:G},Q)),ref:le})},"credential-message-group":{children:(0,t.jsx)(j.Z,{count:1,ref:ie}),sm:2,sx:{display:xe}},"credential-submit":Pe},spacing:y},Y))}));_.displayName="GateForm";var B=_,E=n(3679),F=n(480),H=n(3366),T=n(7462),L=n(7192),U=n(1796),z=n(1964),G=n(3616),$=n(7892),D=(0,$.Z)((0,t.jsx)("path",{d:"M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"}),"RadioButtonUnchecked"),W=(0,$.Z)((0,t.jsx)("path",{d:"M8.465 8.465C9.37 7.56 10.62 7 12 7C14.76 7 17 9.24 17 12C17 13.38 16.44 14.63 15.535 15.535C14.63 16.44 13.38 17 12 17C9.24 17 7 14.76 7 12C7 10.62 7.56 9.37 8.465 8.465Z"}),"RadioButtonChecked"),q=n(1496);const K=(0,q.ZP)("span")({position:"relative",display:"flex"}),X=(0,q.ZP)(D)({transform:"scale(1)"}),Y=(0,q.ZP)(W)((({theme:e,ownerState:r})=>(0,T.Z)({left:0,position:"absolute",transform:"scale(0)",transition:e.transitions.create("transform",{easing:e.transitions.easing.easeIn,duration:e.transitions.duration.shortest})},r.checked&&{transform:"scale(1)",transition:e.transitions.create("transform",{easing:e.transitions.easing.easeOut,duration:e.transitions.duration.shortest})})));var J=function(e){const{checked:r=!1,classes:n={},fontSize:o}=e,l=(0,T.Z)({},e,{checked:r});return(0,t.jsxs)(K,{className:n.root,ownerState:l,children:[(0,t.jsx)(X,{fontSize:o,className:n.background,ownerState:l}),(0,t.jsx)(Y,{fontSize:o,className:n.dot,ownerState:l})]})},Q=n(8216),ee=n(7450);var re=d.createContext(void 0);var ne=n(8979);function te(e){return(0,ne.Z)("MuiRadio",e)}var oe=(0,n(6087).Z)("MuiRadio",["root","checked","disabled","colorPrimary","colorSecondary"]);const le=["checked","checkedIcon","color","icon","name","onChange","size"],ie=(0,q.ZP)(z.Z,{shouldForwardProp:e=>(0,q.FO)(e)||"classes"===e,name:"MuiRadio",slot:"Root",overridesResolver:(e,r)=>{const{ownerState:n}=e;return[r.root,r[`color${(0,Q.Z)(n.color)}`]]}})((({theme:e,ownerState:r})=>(0,T.Z)({color:e.palette.text.secondary,"&:hover":{backgroundColor:(0,U.Fq)("default"===r.color?e.palette.action.active:e.palette[r.color].main,e.palette.action.hoverOpacity),"@media (hover: none)":{backgroundColor:"transparent"}}},"default"!==r.color&&{[`&.${oe.checked}`]:{color:e.palette[r.color].main}},{[`&.${oe.disabled}`]:{color:e.palette.action.disabled}})));const ae=(0,t.jsx)(J,{checked:!0}),se=(0,t.jsx)(J,{});var ue=d.forwardRef((function(e,r){var n,o;const l=(0,G.Z)({props:e,name:"MuiRadio"}),{checked:i,checkedIcon:a=ae,color:s="primary",icon:u=se,name:c,onChange:p,size:f="medium"}=l,h=(0,H.Z)(l,le),v=(0,T.Z)({},l,{color:s,size:f}),m=(e=>{const{classes:r,color:n}=e,t={root:["root",`color${(0,Q.Z)(n)}`]};return(0,T.Z)({},r,(0,L.Z)(t,te,r))})(v),y=d.useContext(re);let b=i;const x=(0,ee.Z)(p,y&&y.onChange);let g=c;var j,w;return y&&("undefined"===typeof b&&(j=y.value,b="object"===typeof(w=l.value)&&null!==w?j===w:String(j)===String(w)),"undefined"===typeof g&&(g=y.name)),(0,t.jsx)(ie,(0,T.Z)({type:"radio",icon:d.cloneElement(u,{fontSize:null!=(n=se.props.fontSize)?n:f}),checkedIcon:d.cloneElement(a,{fontSize:null!=(o=ae.props.fontSize)?o:f}),ownerState:v,classes:m,name:g,checked:b,onChange:x,ref:r},h))})),ce=n(3640),de=n(476),pe=n(3457),fe=n(1705),he=n(9299),ve=n(7909);const me=["actions","children","defaultValue","name","onChange","value"];var ye=d.forwardRef((function(e,r){const{actions:n,children:o,defaultValue:l,name:i,onChange:a,value:s}=e,u=(0,H.Z)(e,me),c=d.useRef(null),[p,f]=(0,he.Z)({controlled:s,default:l,name:"RadioGroup"});d.useImperativeHandle(n,(()=>({focus:()=>{let e=c.current.querySelector("input:not(:disabled):checked");e||(e=c.current.querySelector("input:not(:disabled)")),e&&e.focus()}})),[]);const h=(0,fe.Z)(r,c),v=(0,ve.Z)(i);return(0,t.jsx)(re.Provider,{value:{name:v,onChange:e=>{f(e.target.value),a&&a(e,e.target.value)},value:p},children:(0,t.jsx)(pe.Z,(0,T.Z)({role:"radiogroup",ref:h},u,{children:o}))})})),be=n(2416);function xe(e,r){(null==r||r>e.length)&&(r=e.length);for(var n=0,t=new Array(r);n<r;n++)t[n]=e[n];return t}function ge(e,r,n){return r in e?Object.defineProperty(e,r,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[r]=n,e}function je(e){for(var r=1;r<arguments.length;r++){var n=null!=arguments[r]?arguments[r]:{},t=Object.keys(n);"function"===typeof Object.getOwnPropertySymbols&&(t=t.concat(Object.getOwnPropertySymbols(n).filter((function(e){return Object.getOwnPropertyDescriptor(n,e).enumerable})))),t.forEach((function(r){ge(e,r,n[r])}))}return e}function we(e,r){if(null==e)return{};var n,t,o=function(e,r){if(null==e)return{};var n,t,o={},l=Object.keys(e);for(t=0;t<l.length;t++)n=l[t],r.indexOf(n)>=0||(o[n]=e[n]);return o}(e,r);if(Object.getOwnPropertySymbols){var l=Object.getOwnPropertySymbols(e);for(t=0;t<l.length;t++)n=l[t],r.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}function Ze(e,r){return function(e){if(Array.isArray(e))return e}(e)||function(e,r){var n=null==e?null:"undefined"!==typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(null!=n){var t,o,l=[],i=!0,a=!1;try{for(n=n.call(e);!(i=(t=n.next()).done)&&(l.push(t.value),!r||l.length!==r);i=!0);}catch(s){a=!0,o=s}finally{try{i||null==n.return||n.return()}finally{if(a)throw o}}return l}}(e,r)||function(e,r){if(!e)return;if("string"===typeof e)return xe(e,r);var n=Object.prototype.toString.call(e).slice(8,-1);"Object"===n&&e.constructor&&(n=e.constructor.name);if("Map"===n||"Set"===n)return Array.from(n);if("Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n))return xe(e,r)}(e,r)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}var Pe=function(e){var r=e.formControlProps,n=e.formControlLabelProps,o=e.formLabelProps,l=e.id,i=e.label,a=e.onChange,s=e.radioItems,u=e.radioProps,c=(void 0===u?{}:u).sx,f=e.radioGroupProps,h=we(e.radioProps,["sx"]),v=(0,d.useMemo)((function(){return"string"===typeof i?(0,t.jsx)(be.Ac,{children:i}):i}),[i]),m=(0,d.useMemo)((function(){return Object.entries(s).map((function(e){var r=Ze(e,2),o=r[0],i=r[1],a=i.label,s=i.value,u="string"===typeof a?(0,t.jsx)(be.Ac,{children:a}):a;return(0,t.jsx)(F.Z,je({control:(0,t.jsx)(ue,je({},h,{sx:je(ge({},"&.".concat(oe.root),{color:p.s7}),c)})),value:s,label:u},n),"".concat(l,"-").concat(o))}))}),[n,l,s,c,h]);return(0,t.jsxs)(ce.Z,je({},r,{children:[(0,t.jsx)(de.Z,je({},o,{children:v})),(0,t.jsx)(ye,je({onChange:a,row:!0},f,{children:m}))]}))},Se=n(3144),Ce=n(2749);function Oe(e,r){(null==r||r>e.length)&&(r=e.length);for(var n=0,t=new Array(r);n<r;n++)t[n]=e[n];return t}function ke(e,r,n){return r in e?Object.defineProperty(e,r,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[r]=n,e}function Ae(e,r){return function(e){if(Array.isArray(e))return e}(e)||function(e,r){var n=null==e?null:"undefined"!==typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(null!=n){var t,o,l=[],i=!0,a=!1;try{for(n=n.call(e);!(i=(t=n.next()).done)&&(l.push(t.value),!r||l.length!==r);i=!0);}catch(s){a=!0,o=s}finally{try{i||null==n.return||n.return()}finally{if(a)throw o}}return l}}(e,r)||function(e,r){if(!e)return;if("string"===typeof e)return Oe(e,r);var n=Object.prototype.toString.call(e).slice(8,-1);"Object"===n&&e.constructor&&(n=e.constructor.name);if("Map"===n||"Set"===n)return Array.from(n);if("Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n))return Oe(e,r)}(e,r)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}var Ie="Alteeve enterprise key",Me="Host IP address",Re="Host name",Ve="RedHat password",Ne="RedHat user",_e="enterpriseKey",Be="hostName",Ee="redhatPassword",Fe="redhatUser",He={xs:1,sm:2},Te=function(){var e=(0,Se.Z)().protect,r=(0,d.useRef)({}),n=(0,d.useRef)({}),o=(0,d.useRef)({}),l=(0,d.useRef)({}),P=(0,d.useRef)({}),S=(0,d.useRef)({}),C=(0,d.useRef)({}),O=(0,d.useState)(),k=O[0],A=O[1],I=(0,d.useState)(),M=I[0],R=I[1],V=Ae((0,Ce.Z)(void 0,e),2),N=V[0],_=V[1],F=Ae((0,Ce.Z)("",e),2),H=F[0],T=F[1],L=(0,d.useState)(""),U=L[0],z=L[1],G=(0,d.useState)(!0),$=G[0],D=G[1],W=(0,d.useState)(!1),q=W[0],K=W[1],X=(0,d.useState)(!0),Y=X[0],J=X[1],Q=(0,d.useState)(!0),ee=Q[0],re=Q[1],ne=(0,d.useState)(!1),te=ne[0],oe=ne[1],le=(0,d.useState)(!0),ie=le[0],ae=le[1],se=(0,d.useState)(!1),ue=se[0],ce=se[1],de=(0,d.useState)(!1),pe=de[0],fe=de[1],he=(0,d.useState)(!1),ve=he[0],me=he[1],ye=(0,d.useState)(!1),xe=ye[0],ge=ye[1],je=(0,d.useCallback)((function(e){var r;null===(r=C.current.setMessage)||void 0===r||r.call(null,Be,e)}),[]),we=(0,d.useCallback)((function(e){var r;null===(r=C.current.setMessage)||void 0===r||r.call(null,_e,e)}),[]),Ze=(0,d.useCallback)((function(e){var r;null===(r=C.current.setMessage)||void 0===r||r.call(null,Ee,e)}),[]),Oe=(0,d.useCallback)((function(e){var r;null===(r=C.current.setMessage)||void 0===r||r.call(null,Fe,e)}),[]),Te=(0,d.useCallback)((function(e){var r;return null===(r=C.current.setMessage)||void 0===r?void 0:r.call(null,"submitPrepareHost",e)}),[]),Le=(0,d.useMemo)((function(){var e;return ke(e={},_e,(0,m.$e)(Ie,(function(){we()}),void 0,(function(e){we({children:e,type:"warning"})}))),ke(e,Be,(0,m.Ye)(Re,(function(){je()}),void 0,(function(e){je({children:e,type:"warning"})}))),ke(e,Ee,(0,m.Gn)(Ve,(function(){Ze()}),void 0,(function(e){Ze({children:e,type:"warning"})}))),ke(e,Fe,(0,m.Gn)(Ne,(function(){Oe()}),void 0,(function(e){Oe({children:e,type:"warning"})}))),e}),[we,je,Ze,Oe]),Ue=(0,d.useMemo)((function(){return(0,m.LT)(Le)}),[Le]),ze=(0,d.useMemo)((function(){return ve?void 0:"none"}),[ve]),Ge=(0,d.useMemo)((function(){return(0,t.jsx)(B,{allowSubmit:ie,gridProps:{wrapperBoxProps:{sx:{display:te?"flex":"none"}}},identifierInputTestBatchBuilder:function(e){return(0,m._)(Me,(function(){e()}),void 0,(function(r){e({children:r,type:"warning"})}))},identifierLabel:Me,onIdentifierBlurAppend:function(e){var r=e.target.value;if(M){var n=r!==M;ae(n),ce(!n),me(!n)}},onSubmitAppend:function(e,r,n,t){var o=e.getValue,i=r.getValue,a=null===o||void 0===o?void 0:o.call(null),s=null===i||void 0===i?void 0:i.call(null);h.Z.put("/command/inquire-host",{ipAddress:a,password:s}).then((function(e){var r=e.data,t=r.hostName,o=r.hostOS,i=r.hostUUID,u=r.isConnected,c=r.isInetConnected,d=r.isOSRegistered;if(u){var p;null===(p=l.current.setValue)||void 0===p||p.call(null,t);var f=Ue({inputs:ke({},Be,{value:t})});K(f),c&&/rhel/i.test(o)&&!d&&me(!0),R(a),_(s),T(i),ae(!1),ce(!0)}else null===n||void 0===n||n.call(null,{children:"Failed to establish a connection with the given host credentials.",type:"error"})})).catch((function(e){var r=(0,v.Z)(e);null===n||void 0===n||n.call(null,r)})).finally((function(){t(!1)}))},passphraseLabel:"Host root password",ref:n,submitLabel:"Test access"})}),[te,ie,M,_,T,Ue]),$e=(0,d.useMemo)((function(){return(0,t.jsx)(i.Z,{columns:He,layout:{"preparehost-host-name":{children:(0,t.jsx)(g.Z,{input:(0,t.jsx)(w.Z,{formControlProps:{sx:{width:"100%"}},id:"preparehost-host-name-input",inputProps:{onBlur:function(e){var r=e.target.value,n=Ue({inputs:ke({},Be,{value:r})});K(n)},onFocus:function(){je()}},label:Re}),ref:l})},"preparehost-enterprise-key":{children:(0,t.jsx)(g.Z,{input:(0,t.jsx)(w.Z,{formControlProps:{sx:{width:"100%"}},id:"preparehost-enterprise-key-input",inputProps:{onBlur:function(e){var r=e.target.value;if(r){var n=Ue({inputs:ke({},_e,{value:r})});D(n)}},onFocus:function(){we()}},label:Ie}),ref:o})}},spacing:"1em",wrapperBoxProps:{sx:{display:ue?void 0:"none"}}})}),[ue,we,je,Ue]),De=(0,d.useMemo)((function(){return(0,t.jsx)(i.Z,{columns:He,layout:{"preparehost-redhat-user":{children:(0,t.jsx)(g.Z,{input:(0,t.jsx)(w.Z,{formControlProps:{sx:{width:"100%"}},id:"preparehost-redhat-user-input",inputProps:{onBlur:function(e){var r=e.target.value;if(r){var n=Ue({inputs:ke({},Fe,{value:r})});re(n)}},onFocus:function(){Oe()}},label:Ne}),ref:S})},"preparehost-redhat-password":{children:(0,t.jsx)(g.Z,{input:(0,t.jsx)(w.Z,{formControlProps:{sx:{width:"100%"}},id:"preparehost-redhat-password-input",inputProps:{onBlur:function(e){var r=e.target.value;if(r){var n=Ue({inputs:ke({},Ee,{value:r})});J(n)}},onFocus:function(){Ze()},onPasswordVisibilityAppend:function(e){fe(e!==f.Z.password)},type:f.Z.password},label:Ve}),ref:P})}},spacing:"1em",wrapperBoxProps:{sx:{display:ze}}})}),[ze,Ze,Oe,Ue]),We=(0,d.useMemo)((function(){return(0,t.jsx)(u.Z,{sx:{display:ue?void 0:"none"},children:(0,t.jsx)(j.Z,{count:1,ref:C})})}),[ue]),qe=(0,d.useMemo)((function(){return xe?(0,t.jsx)(Z.Z,{mt:0}):(0,t.jsx)(x.Z,{row:!0,sx:{display:ue?"flex":"none",justifyContent:"flex-end"},children:(0,t.jsx)(b.Z,{disabled:!q||!$||!ee||!Y,onClick:function(){var e,n,t,i,a,s=null===(e=P.current.getValue)||void 0===e?void 0:e.call(null);A({enterpriseKey:(null===(n=o.current.getValue)||void 0===n?void 0:n.call(null))||"none; using community version",hostName:(null===(t=l.current.getValue)||void 0===t?void 0:t.call(null))||"",redhatPassword:s||"none",redhatPasswordHidden:(null===s||void 0===s?void 0:s.replace(/./g,"*"))||"none",redhatUser:(null===(i=S.current.getValue)||void 0===i?void 0:i.call(null))||"none"}),Te(),null===(a=r.current.setOpen)||void 0===a||a.call(null,!0)},children:"Prepare host"})})}),[$,q,Y,ee,ue,xe,Te]);return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsxs)(E.s_,{children:[(0,t.jsx)(E.V9,{children:(0,t.jsx)(be.z,{children:"Prepare a host to include in Anvil!"})}),(0,t.jsxs)(x.Z,{children:[(0,t.jsx)(Pe,{id:"preparehost-host-type",label:"Host type",onChange:function(e,r){z(r),oe(!0)},radioItems:{node:{label:"Node",value:"node"},dr:{label:"Disaster Recovery (DR) host",value:"dr"}}}),Ge,$e,De,We,qe]})]}),(0,t.jsx)(y.Z,{actionProceedText:"Prepare",closeOnProceed:!0,content:(0,t.jsx)(i.Z,{calculateItemBreakpoints:function(e){return{xs:e%2===0?1:2}},columns:3,layout:{"preparehost-confirm-host-type-label":{children:(0,t.jsx)(be.Ac,{children:"Host type"})},"preparehost-confirm-host-type-value":{children:(0,t.jsx)(be.$_,{children:"dr"===U?"Disaster Recovery (DR)":"Node"})},"preparehost-confirm-host-name-label":{children:(0,t.jsx)(be.Ac,{children:"Host name"})},"preparehost-confirm-host-name-value":{children:(0,t.jsx)(be.$_,{children:null===k||void 0===k?void 0:k.hostName})},"preparehost-confirm-enterprise-key-label":{children:(0,t.jsx)(be.Ac,{children:"Alteeve enterprise key"})},"preparehost-confirm-enterprise-key-value":{children:(0,t.jsx)(be.$_,{children:null===k||void 0===k?void 0:k.enterpriseKey})},"preparehost-confirm-redhat-user-label":{children:(0,t.jsx)(be.Ac,{children:"RedHat user"}),sx:{display:ze}},"preparehost-confirm-redhat-user-value":{children:(0,t.jsx)(be.$_,{children:null===k||void 0===k?void 0:k.redhatUser}),sx:{display:ze}},"preparehost-confirm-redhat-password-label":{children:(0,t.jsx)(be.Ac,{children:"RedHat password"}),sx:{display:ze}},"preparehost-confirm-redhat-password-value":{children:(0,t.jsxs)(x.Z,{row:!0,sx:{height:"100%",maxWidth:"100%"},children:[(0,t.jsx)(be.$_,{sx:{flexGrow:1,maxWidth:"calc(100% - 3em)",overflowX:"scroll"},children:pe?null===k||void 0===k?void 0:k.redhatPassword:null===k||void 0===k?void 0:k.redhatPasswordHidden}),(0,t.jsx)(c.Z,{onClick:function(){fe((function(e){return!e}))},sx:{color:p.s7,padding:0},children:pe?(0,t.jsx)(a.Z,{}):(0,t.jsx)(s.Z,{})})]}),sx:{display:ze}}},spacing:".6em"}),onCancelAppend:function(){fe(!1)},onProceedAppend:function(){var e,r,n,t;ge(!0),h.Z.put("/host/prepare",{enterpriseUUID:null===(e=o.current.getValue)||void 0===e?void 0:e.call(null),hostIPAddress:M,hostName:null===(r=l.current.getValue)||void 0===r?void 0:r.call(null),hostPassword:N,hostType:U,hostUUID:H,redhatPassword:null===(n=P.current.getValue)||void 0===n?void 0:n.call(null),redhatUser:null===(t=S.current.getValue)||void 0===t?void 0:t.call(null)}).then((function(){Te({children:"Successfully initiated prepare host."}),setTimeout((function(){Te()}),5e3)})).catch((function(e){var r=(0,v.Z)(e,{onResponseErrorAppend:function(e){var r;return 400===e.status&&(r={children:"The API found invalid values. Did you forget to fill in one of the RedHat fields?",type:"warning"}),r}});Te(r)})).finally((function(){ge(!1)}))},ref:r,titleText:"Confirm host preparation"})]})},Le=function(){return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(o.default,{children:(0,t.jsx)("title",{children:"Prepare Host"})}),(0,t.jsx)(l.Z,{}),(0,t.jsx)(i.Z,{columns:{xs:1,sm:6,md:4},layout:{"preparehost-left-column":{sm:1,xs:0},"preparehost-center-column":{children:(0,t.jsx)(Te,{}),md:2,sm:4,xs:1}}})]})}},9008:function(e,r,n){e.exports=n(5443)}},function(e){e.O(0,[738,688,7,619,315,818,141,892,384,774,888,179],(function(){return r=3187,e(e.s=r);var r}));var r=e.O();_N_E=r}]);