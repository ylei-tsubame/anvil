"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[86],{1939:function(e,n,t){var r=t(5893),o=t(7357),i=t(7169);function u(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function a(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{},r=Object.keys(t);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(t).filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable})))),r.forEach((function(n){u(e,n,t[n])}))}return e}function l(e,n){if(null==e)return{};var t,r,o=function(e,n){if(null==e)return{};var t,r,o={},i=Object.keys(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||(o[t]=e[t]);return o}(e,n);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(o[t]=e[t])}return o}var c="Decorator",s={ok:"".concat(c,"-ok"),warning:"".concat(c,"-warning"),error:"".concat(c,"-error"),off:"".concat(c,"-off")};n.Z=function(e){var n,t=e.colour,c=e.sx,f=l(e,["colour","sx"]);return(0,r.jsx)(o.Z,a({},f,{className:s[t],sx:a((n={borderRadius:i.n_,height:"100%",width:"1.4em"},u(n,"&.".concat(s.ok),{backgroundColor:i.Ej}),u(n,"&.".concat(s.warning),{backgroundColor:i.Wd}),u(n,"&.".concat(s.error),{backgroundColor:i.hM}),u(n,"&.".concat(s.off),{backgroundColor:i.s7}),n),c)}))}},5741:function(e,n,t){var r=t(5893),o=t(1714),i=t(122),u=t(7169),a=t(4690);function l(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function c(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{},r=Object.keys(t);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(t).filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable})))),r.forEach((function(n){l(e,n,t[n])}))}return e}function s(e,n){if(null==e)return{};var t,r,o=function(e,n){if(null==e)return{};var t,r,o={},i=Object.keys(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||(o[t]=e[t]);return o}(e,n);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(o[t]=e[t])}return o}n.Z=function(e){var n=e.children,t=e.sx,l=s(e,["children","sx"]);return(0,r.jsx)(i.Z,c({underline:"hover",variant:"subtitle1"},l,{sx:c({color:u.lD,textDecorationColor:u.s7},t),children:(0,r.jsxs)(a.Z,{row:!0,children:[n,(0,r.jsx)(o.Z,{sx:{marginLeft:".3em"}})]})}))}},4596:function(e,n,t){t.d(n,{Z:function(){return fe}});var r=t(5893),o=t(7357),i=t(2734),u=t(8396),a=t(6239),l=t(9699),c=t(2026),s=t(5537),f=t(2428),d=t(2275),v=t(3490),p=t(8951),m=t(7294),b=t(5934),g=t(2029),y=t(7169),h=t(3106),w=t(1250),k=t(4390),x=t(4799),I=t(1939),j=t(7750);function C(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function O(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{},r=Object.keys(t);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(t).filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable})))),r.forEach((function(n){C(e,n,t[n])}))}return e}function M(e,n){if(null==e)return{};var t,r,o=function(e,n){if(null==e)return{};var t,r,o={},i=Object.keys(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||(o[t]=e[t]);return o}(e,n);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(o[t]=e[t])}return o}var S=function(e){var n=e.isFloating,t=e.networkInterface,i=t.networkInterfaceName,u=t.networkInterfaceState,a=e.onClose,l=e.sx,c=M(e,["isFloating","networkInterface","onClose","sx"]),f=n?{borderColor:y.s7,borderRadius:y.n_,borderStyle:"solid",borderWidth:"1px",backgroundColor:y.E5,padding:".6em 1.2em"}:{};return(0,r.jsxs)(o.Z,O({sx:O({display:"flex",flexDirection:"row","& > :not(:first-child)":{alignSelf:"center",marginLeft:".5em"}},f,l)},c,{children:[(0,r.jsx)(I.Z,{colour:"up"===u?"ok":"off",sx:{height:"auto"}}),(0,r.jsx)(j.Ac,{text:i}),a&&(0,r.jsx)(x.Z,{onClick:a,size:"small",sx:{color:y.s7},children:(0,r.jsx)(s.Z,{})})]}))};S.defaultProps={isFloating:!1,onClose:void 0};var U=S,Z=(0,t(1496).ZP)(o.Z)((function(){return{borderColor:y.s7,borderStyle:"dashed",borderWidth:"4px",display:"flex",flexDirection:"column",padding:".6em","& > :not(:first-child)":{marginTop:".3em"}}})),D=t(4690),P=t(1770),A=t(1706),N=t(9099),R=t(7869),E=t(6284),T=t(3679),V=t(1905),F=t(7783),L=t(2152),q=t(7987);function H(e,n){(null==n||n>e.length)&&(n=e.length);for(var t=0,r=new Array(n);t<n;t++)r[t]=e[t];return r}function B(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function _(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{},r=Object.keys(t);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(t).filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable})))),r.forEach((function(n){B(e,n,t[n])}))}return e}function G(e,n){if(null==e)return{};var t,r,o=function(e,n){if(null==e)return{};var t,r,o={},i=Object.keys(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||(o[t]=e[t]);return o}(e,n);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(o[t]=e[t])}return o}function $(e,n){return function(e){if(Array.isArray(e))return e}(e)||function(e,n){var t=null==e?null:"undefined"!==typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(null!=t){var r,o,i=[],u=!0,a=!1;try{for(t=t.call(e);!(u=(r=t.next()).done)&&(i.push(r.value),!n||i.length!==n);u=!0);}catch(l){a=!0,o=l}finally{try{u||null==t.return||t.return()}finally{if(a)throw o}}return i}}(e,n)||W(e,n)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}function J(e){return function(e){if(Array.isArray(e))return H(e)}(e)||function(e){if("undefined"!==typeof Symbol&&null!=e[Symbol.iterator]||null!=e["@@iterator"])return Array.from(e)}(e)||W(e)||function(){throw new TypeError("Invalid attempt to spread non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}function W(e,n){if(e){if("string"===typeof e)return H(e,n);var t=Object.prototype.toString.call(e).slice(8,-1);return"Object"===t&&e.constructor&&(t=e.constructor.name),"Map"===t||"Set"===t?Array.from(t):"Arguments"===t||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t)?H(e,n):void 0}}var X={ifaceNotApplied:"".concat("NetworkInitForm","-network-interface-not-applied")},z=[void 0,void 0],K="dns",Y="gateway",Q=function(e){return"".concat(e,"Interface")},ee=function(e){return"".concat(e,"IPAddress")},ne=function(e){return"".concat(e,"Name")},te=function(e){return"".concat(e,"SubnetMask")},re=function(e){return"".concat(e,"NetworkSubnetConflict")},oe=Array.from({length:2},(function(e,n){return n+1})),ie={bcn:{ip:function(e){var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"";return"10.20".concat(e,".").concat(n)},mask:"255.255.0.0"},ifn:{ip:function(){return""},mask:""},mn:{ip:function(){return"10.199."},mask:"255.255.0.0"},sn:{ip:function(e){var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"";return"10.10".concat(e,".").concat(n)},mask:"255.255.0.0"}},ue=function(e){return"network".concat(e)},ae=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},n=e.inputUUID,t=void 0===n?(0,b.Z)():n,r=e.interfaces,o=void 0===r?J(z):r,i=e.ipAddress,u=void 0===i?"":i,a=e.name,l=e.subnetMask,c=void 0===l?"":l,s=e.type,f=void 0===s?"":s,d=e.typeCount,v=void 0===d?0:d,p=G(e,["inputUUID","interfaces","ipAddress","name","subnetMask","type","typeCount"]),m=a;return a||(m=h.Z[f]&&v>0?"".concat(h.Z[f]," ").concat(v):"Unknown Network"),_({inputUUID:t,interfaces:o,ipAddress:u,name:m,subnetMask:c,type:f,typeCount:v},p)},le=function(e,n){return[{align:"center",field:"",renderCell:function(t){var i,u=t.row,a=(null!==(i=n[u.networkInterfaceUUID])&&void 0!==i&&i).isApplied,s="grab",f=function(){for(var n=arguments.length,t=new Array(n),r=0;r<n;r++)t[r]=arguments[r];e.apply(void 0,[u].concat(J(t)))},d=(0,r.jsx)(l.Z,{});return a&&(s="auto",f=void 0,d=(0,r.jsx)(c.Z,{sx:{color:y.Ej}})),(0,r.jsx)(o.Z,{onMouseDown:f,sx:{alignItems:"center",display:"flex",flexDirection:"row","&:hover":{cursor:s}},children:d})},sortable:!1,width:1},{field:"networkInterfaceName",flex:1,headerName:"Name",renderCell:function(e){var n=e.row,t=(void 0===n?{}:n).networkInterfaceState,i=e.value;return(0,r.jsxs)(o.Z,{sx:{display:"flex",flexDirection:"row","& > :not(:first-child)":{marginLeft:".5em"}},children:[(0,r.jsx)(I.Z,{colour:"up"===t?"ok":"off",sx:{height:"auto"}}),(0,r.jsx)(j.KI,{text:i})]})}},{field:"networkInterfaceMACAddress",flex:1,headerName:"MAC",renderCell:function(e){var n=e.value;return(0,r.jsx)(j.$_,{text:n})}},{field:"networkInterfaceState",flex:1,headerName:"State",renderCell:function(e){var n=e.value,t=String(n);return(0,r.jsx)(j.KI,{text:"".concat(t.charAt(0).toUpperCase()).concat(t.substring(1))})}},{field:"networkInterfaceSpeed",flex:1,headerName:"Speed",renderCell:function(e){var n=e.value;return(0,r.jsx)(j.KI,{text:"".concat(parseFloat(n).toLocaleString()," Mbps")})}},{field:"networkInterfaceOrder",flex:1,headerName:"Order"}]},ce=function(e){var n=e.allowMigrationNetwork,t=e.createDropMouseUpHandler,a=e.getNetworkTypeCount,l=e.hostDetail,c=void 0===l?{}:l,d=c.hostType,v=c.sequence,p=e.networkIndex,b=e.networkInput,g=e.networkInterfaceCount,w=e.networkInterfaceInputMap,k=e.removeNetwork,x=e.setMessageRe,I=e.setNetworkInputs,C=e.setNetworkInterfaceInputMap,O=e.testInput,M=e.testInputToToggleSubmitDisabled,S=(0,i.Z)(),D=(0,u.Z)(S.breakpoints.up("md")),P=(0,u.Z)(S.breakpoints.up("lg")),R=(0,m.useRef)({}),V=(0,m.useRef)({}),L=b.inputUUID,q=b.interfaces,H=b.ipAddress,G=b.isRequired,W=b.subnetMask,X=b.type,z=b.typeCount,K=(0,m.useMemo)((function(){return ue(L)}),[L]),Y=(0,m.useMemo)((function(){return Q(K)}),[K]),ne=(0,m.useMemo)((function(){return ee(K)}),[K]),ae=(0,m.useMemo)((function(){return te(K)}),[K]),le=(0,m.useMemo)((function(){return re(K)}),[K]),ce=(0,m.useMemo)((function(){return"node"===d}),[d]),se=(0,m.useMemo)((function(){return!ce&&g<=2?[1]:oe}),[ce,g]),fe=(0,m.useMemo)((function(){var e=h.Z.bcn,t=h.Z.ifn,r=h.Z.mn,o=h.Z.sn;return ce&&g>=8&&(n||"mn"===X)?{bcn:e,ifn:t,mn:r,sn:o}:{bcn:e,ifn:t,sn:o}}),[n,ce,g,X]),de=(0,m.useCallback)((function(e,n,t){var r=R.current,o=r.getIsChangedByUser,i=r.setValue,u=V.current,a=u.getIsChangedByUser,l=u.setValue;(null===o||void 0===o?void 0:o.call(null))||(e.ipAddress=n,null===i||void 0===i||i.call(null,n)),(null===a||void 0===a?void 0:a.call(null))||(e.subnetMask=t,null===l||void 0===l||l.call(null,t))}),[]);return(0,m.useEffect)((function(){var e,n;"striker"===d&&"ifn"!==X&&(!(null===(e=R.current.getIsChangedByUser)||void 0===e?void 0:e.call(null))&&Number(v)&&(null===(n=R.current.setValue)||void 0===n||n.call(null,H.replace(/^((?:\d+\.){3})\d*$/,"$1".concat(v)))))}),[d,H,v,X]),(0,m.useEffect)((function(){var e=b.ipAddressInputRef,n=b.subnetMaskInputRef;e===R&&n===V||(b.ipAddressInputRef=R,b.subnetMaskInputRef=V,I((function(e){return J(e)})))}),[b,I]),(0,r.jsxs)(T.Lg,{children:[(0,r.jsxs)(T.CH,{children:[(0,r.jsx)(F.Z,{id:"network-".concat(L,"-name"),isReadOnly:G,inputLabelProps:{isNotifyRequired:!0},label:"Network name",selectItems:Object.entries(fe).map((function(e){var n=$(e,2),t=n[0],r=n[1],o=a(t,{lastIndex:p});return t!==X&&(o+=1),{value:t,displayValue:"".concat(r," ").concat(o)}})),selectProps:{onChange:function(e){var n=e.target.value,t=String(n);b.type=t;var r=a(t,{lastIndex:p});b.typeCount=r,b.name="".concat(h.Z[t]," ").concat(r);var o=ie[t];if(o){var i,u=o.ip,l=o.mask;"striker"===d&&"bcn"===t&&(i="4."),de(b,u(r,i),l)}I((function(e){return J(e)}))},renderValue:P?void 0:function(e){return"".concat(String(e).toUpperCase()," ").concat(z)},value:X}}),!G&&(0,r.jsx)(A.Z,{onClick:function(){k(p)},sx:{padding:".2em",position:"absolute",right:"-9px",top:"-4px"},children:(0,r.jsx)(s.Z,{fontSize:"small"})})]}),(0,r.jsxs)(o.Z,{sx:{display:"flex",flexDirection:"column",margin:".6em","& > :not(:first-child)":{marginTop:"1em"}},children:[se.map((function(e){var n="Link ".concat(e),i=e-1,u=q[i],a=(null!==u&&void 0!==u?u:{}).networkInterfaceUUID,l=void 0===a?"":a,c=D?(0,r.jsx)(j.Ac,{text:"Drop to add interface."}):(0,r.jsx)(f.Z,{sx:{alignSelf:"center",color:y.s7}});return(0,r.jsxs)(o.Z,{sx:{alignItems:"center",display:"flex",flexDirection:"row","& > :not(:first-child)":{marginLeft:"1em"},"& > :last-child":{flexGrow:1}},children:[(0,r.jsx)(j.Ac,{sx:{whiteSpace:"nowrap"},text:n}),(0,r.jsx)(Z,{onMouseUp:function(){for(var e=arguments.length,n=new Array(e),r=0;r<e;r++)n[r]=arguments[r];var o;null===(o=null===t||void 0===t?void 0:t.call(null,q,i))||void 0===o||o.call.apply(o,[null].concat(J(n))),M({inputs:B({},Y,{isIgnoreOnCallbacks:!1}),isContinueOnFailure:!0})},children:u?(0,r.jsx)(U,{networkInterface:u,onClose:function(){q[i]=void 0,w[l].isApplied=!1,C((function(e){return _({},e)})),M({inputs:B({},Y,{isIgnoreOnCallbacks:!1}),isContinueOnFailure:!0})}},"network-interface-".concat(l)):c})]},"network-".concat(L,"-link-").concat(e))})),(0,r.jsx)(N.Z,{input:(0,r.jsx)(E.Z,{id:"network-".concat(L,"-ip-address"),inputProps:{onBlur:function(e){var n=e.target.value;O({inputs:B({},ne,{value:n})})}},inputLabelProps:{isNotifyRequired:!0},label:"IP address",onChange:function(e){var n=e.target.value;M({inputs:B({},ne,{value:n})}),x(RegExp("(?:^(?:".concat(ne,"|").concat(le,")|").concat(L,"$)")))},value:H}),ref:R}),(0,r.jsx)(N.Z,{input:(0,r.jsx)(E.Z,{id:"network-".concat(L,"-subnet-mask"),inputProps:{onBlur:function(e){var n=e.target.value;O({inputs:B({},ae,{value:n})})}},inputLabelProps:{isNotifyRequired:!0},label:"Subnet mask",onChange:function(e){var n=e.target.value;M({inputs:B({},ae,{value:n})}),x(RegExp("(?:^(?:".concat(ae,"|").concat(le,")|").concat(L,"$)")))},value:W}),ref:V})]})]})};ce.defaultProps={allowMigrationNetwork:!0,createDropMouseUpHandler:void 0,hostDetail:void 0};var se=(0,m.forwardRef)((function(e,n){var t,i=e.expectHostDetail,u=void 0!==i&&i,l=e.hostDetail,c=e.hostSequence,s=e.toggleSubmitDisabled,x="local",I=c;if(u){if(l){var j;t=(j=l).hostType,x=j.hostUUID,I=j.sequence}}else t="striker";var C,O,M=(0,m.useMemo)((function(){var e=[];if("striker"===t){var n=I?"10.201.4.".concat(I):"10.201.4.";return e.push(ae({ipAddress:n,isRequired:!0,subnetMask:"255.255.0.0",type:"bcn",typeCount:1}),ae({isRequired:!0,type:"ifn",typeCount:1})),e}return e.push(ae({ipAddress:"10.201.",isRequired:!0,subnetMask:"255.255.0.0",type:"bcn",typeCount:1}),ae({isRequired:!0,type:"ifn",typeCount:1}),ae({ipAddress:"10.101.",isRequired:!0,subnetMask:"255.255.0.0",type:"sn",typeCount:1})),e}),[t,I]),S=(0,m.useMemo)((function(){return"node"===t?{bcn:1,ifn:1,sn:1}:{bcn:1,ifn:1}}),[t]),Z=(0,m.useState)({x:0,y:0}),T=Z[0],F=Z[1],H=(0,m.useState)({}),G=H[0],W=H[1],z=(0,m.useState)(M),oe=z[0],ie=z[1],se=(0,m.useState)(),fe=se[0],de=se[1],ve=(0,m.useState)(""),pe=ve[0],me=ve[1],be=(0,m.useRef)({}),ge=(0,m.useRef)({}),ye=(0,m.useRef)(!0),he=(0,m.useRef)({}),we=(0,V.Z)("".concat(g.Z,"/init/network-interface/").concat(x),{refreshInterval:2e3,onSuccess:function(e){var n=e.reduce((function(e,n){var t,r=n.networkInterfaceUUID;return e[r]=null!==(t=G[r])&&void 0!==t?t:{metadata:n},e}),{});W(n)}}),ke=we.data,xe=void 0===ke?[]:ke,Ie=we.isLoading,je=(0,m.useMemo)((function(){return oe.length>=xe.length||Object.values(G).every((function(e){return e.isApplied}))||"node"===t&&xe.length<=6}),[t,oe,xe,G]),Ce=(0,m.useMemo)((function(){return u&&!l}),[u,l]),Oe=(0,m.useMemo)((function(){return oe.every((function(e){return"mn"!==e.type}))}),[oe]),Me=(0,m.useCallback)((function(e,n){var t;return null===(t=he.current.setMessage)||void 0===t?void 0:t.call(null,e,n)}),[]),Se=(0,m.useCallback)((function(e,n){var t;return null===(t=he.current.setMessageRe)||void 0===t?void 0:t.call(null,e,n)}),[]),Ue=(0,m.useCallback)((function(e){return Me(K,e)}),[Me]),Ze=(0,m.useCallback)((function(e){return Me(Y,e)}),[Me]),De=(0,m.useCallback)((function(e){var n,t=e.fn,r=void 0===t?"every":t,o=e.ip,i=void 0===o?"":o,u=e.mask,a=void 0===u?"":u,l=e.isNegateMatch,c=void 0===l?"every"===r:l,s=e.onMatch,f=e.onMiss,d=e.skipUUID,v="every"===r;try{n=new p.Netmask("".concat(i,"/").concat(a))}catch(m){}return oe[r]((function(e){var t,r,o=e.inputUUID,u=e.ipAddressInputRef,a=e.subnetMaskInputRef;if(o===d)return v;var l=null===(t=null===u||void 0===u?void 0:u.current.getValue)||void 0===t?void 0:t.call(null),b=null===(r=null===a||void 0===a?void 0:a.current.getValue)||void 0===r?void 0:r.call(null),g=!1;try{g=function(e,n){var t=n.b,r=n.bIP,o=void 0===r?"":r;return e.contains(null!==t&&void 0!==t?t:o)||void 0!==t&&t.contains(e)}(new p.Netmask("".concat(l,"/").concat(b)),{b:n,bIP:i})}catch(m){}return g?null===s||void 0===s||s.call(null,e):null===f||void 0===f||f.call(null,e),c?!g:g}))}),[oe]),Pe=(0,m.useCallback)((function(e){k.Z.put("/init/set-map-network",{value:e}).catch((function(n){var t=(0,P.Z)(n);t.children=(0,r.jsxs)(r.Fragment,{children:["Failed to ",e?"enable":"disable"," network mapping."," ",t.children]}),Me("api",t)}))}),[Me]),Ae=(0,m.useMemo)((function(){var e,n=(B(e={},K,{defaults:{getValue:function(){var e;return null===(e=be.current.getValue)||void 0===e?void 0:e.call(null)},onSuccess:function(){Ue()}},tests:[{onFailure:function(){Ue({children:"Domain name servers should be a comma-separated list of IPv4 addresses without trailing comma(s)."})},test:function(e){var n=e.value;return w.ah.test(n)}},{test:q.HJ}]}),B(e,Y,{defaults:{getValue:function(){var e;return null===(e=ge.current.getValue)||void 0===e?void 0:e.call(null)},onSuccess:function(){Ze()}},tests:[{onFailure:function(){Ze({children:"Gateway should be a valid IPv4 address."})},test:function(e){var n=e.value;return w.tf.test(n)}},{test:function(e){var n=e.value,t=!0,r=De({fn:"some",ip:n,onMatch:function(e){var r=e.ipAddress,o=e.name,i=e.type,u=e.typeCount;if(n===r)return t=!1,void Ze({children:"Gateway cannot be the same as IP address in ".concat(o,".")});me("".concat(i).concat(u))}});return r||Ze({children:"Gateway must be in one network's subnet."}),r&&t}},{test:q.HJ}]}),e);return oe.forEach((function(e){var t,r,o=e.inputUUID,i=e.interfaces,u=e.ipAddressInputRef,a=e.name,l=e.subnetMaskInputRef,c=ue(o),s=Q(c),f=ee(c),d=te(c),v=function(e){return Me(s,e)},p=function(e){return Me(f,e)},m=function(e){return Me(d,e)},b=function(e,n,t){var r,o="".concat(re(c),"-").concat(n),i="".concat(re(ue(n)),"-").concat(e);Me((null===(r=he.current.exists)||void 0===r?void 0:r.call(null,i))?i:o,t)},g=function(e){var n=e.ip,i=void 0===n?null===(t=null===u||void 0===u?void 0:u.current.getValue)||void 0===t?void 0:t.call(null):n,c=e.mask,s=void 0===c?null===(r=null===l||void 0===l?void 0:l.current.getValue)||void 0===r?void 0:r.call(null):c;return De({ip:i,mask:s,onMatch:function(e){var n=e.inputUUID,t=e.name;b(o,n,{children:'"'.concat(a,'" and "').concat(t,'" cannot be in the same subnet.')})},onMiss:function(e){var n=e.inputUUID;b(o,n)},skipUUID:o})};n[s]={defaults:{getCompare:function(){return i.map((function(e){return void 0!==e}))},onSuccess:function(){v()}},tests:[{onFailure:function(){v({children:"".concat(a," must have at least 1 interface.")})},test:function(e){return e.compare.some((function(e){return e}))}},{onFailure:function(){v({children:"".concat(a," must have a Link 1 interface.")})},test:function(e){var n=$(e.compare,2),t=n[0];return!(n[1]&&!t)}}]},n[f]={defaults:{getValue:function(){var e;return null===(e=null===u||void 0===u?void 0:u.current.getValue)||void 0===e?void 0:e.call(null)},onSuccess:function(){p()}},tests:[{onFailure:function(){p({children:"IP address in ".concat(a," must be a valid IPv4 address.")})},test:function(e){var n=e.value;return w.tf.test(n)}},{test:function(e){var n=e.value;return g({ip:n})}},{test:q.HJ}]},n[ne(c)]={defaults:{value:a},tests:[{test:q.HJ}]},n[d]={defaults:{getValue:function(){var e;return null===(e=null===l||void 0===l?void 0:l.current.getValue)||void 0===e?void 0:e.call(null)},onSuccess:function(){m()}},tests:[{onFailure:function(){m({children:"Subnet mask in ".concat(a," must be a valid IPv4 address.")})},test:function(e){var n=e.value;return w.tf.test(n)}},{test:function(e){var n=e.value;return g({mask:n})}},{test:q.HJ}]}})),n}),[oe,Ue,Ze,Me,De]),Ne=(0,m.useMemo)((function(){return(0,q.LT)(Ae)}),[Ae]),Re=(0,m.useCallback)((function(e){null===s||void 0===s||s.call(null,Ne(_({isIgnoreOnCallbacks:!0,isTestAll:!0},e)))}),[Ne,s]),Ee=(0,m.useCallback)((function(){de(void 0)}),[]),Te=(0,m.useCallback)((function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};oe.unshift(ae(e)),null===s||void 0===s||s.call(null,!1),ie(J(oe))}),[oe,s]),Ve=(0,m.useCallback)((function(e){var n=$(oe.splice(e,1),1)[0],t=n.inputUUID;n.interfaces.forEach((function(e){if(void 0!==e){var n=e.networkInterfaceUUID;G[n].isApplied=!1}})),Re({excludeTestIdsRe:RegExp(t)}),ie(J(oe)),W((function(e){return _({},e)}))}),[oe,G,Re]),Fe=(0,m.useCallback)((function(e){for(var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},t=n.inputs,r=void 0===t?oe:t,o=n.lastIndex,i=void 0===o?0:o,u=0,a=r.length-1;a>=i;a-=1)r[a].type===e&&(u+=1);return u}),[oe]),Le=(0,m.useMemo)((function(){if(void 0!==fe){var e=fe.networkInterfaceUUID;return function(n,t){return function(){var r,o=(null!==(r=n[t])&&void 0!==r?r:{}).networkInterfaceUUID;o&&o!==e&&(G[o].isApplied=!1),n[t]=fe,G[e].isApplied=!0}}}}),[fe,G]),qe=(0,m.useMemo)((function(){return fe?{cursor:"grabbing",userSelect:"none"}:{}}),[fe]),He=(0,m.useMemo)((function(){if(void 0===fe)return(0,r.jsx)(r.Fragment,{});var e=T.x,n=T.y;return(0,r.jsx)(U,{isFloating:!0,networkInterface:fe,sx:{left:"calc(".concat(e,"px + .4em)"),position:"absolute",top:"calc(".concat(n,"px - 1.6em)"),zIndex:20}})}),[T,fe]),Be=(0,m.useMemo)((function(){return fe?function(){Ee()}:void 0}),[Ee,fe]),_e=(0,m.useMemo)((function(){return fe?function(e){var n=e.currentTarget,t=e.nativeEvent,r=t.clientX,o=t.clientY,i=n.getBoundingClientRect(),u=i.left,a=i.top;F({x:r-u,y:o-a})}:void 0}),[fe]),Ge=(0,m.useMemo)((function(){return fe?function(){Ee()}:void 0}),[Ee,fe]);(0,m.useEffect)((function(){if([Object.keys(G).length>0,u,l,ye.current,be.current,ge.current].every((function(e){return Boolean(e)}))){var e,n;ye.current=!1;var t=l.dns,r=l.gateway,o=l.gatewayInterface,i=l.networks;if([t,r,o,i].some((function(e){return!e})))return;null===(e=be.current.setValue)||void 0===e||e.call(null,t),null===(n=ge.current.setValue)||void 0===n||n.call(null,r);var a=[],c=Object.values(i).reduce((function(e,n){var t,r,o=n.ip,i=n.link1Uuid,u=n.link2Uuid,l=void 0===u?"":u,c=n.subnetMask,s=n.type,f=Fe(s,{inputs:e})+1,d=S[s]===f,v="".concat(h.Z[s]," ").concat(f);return a.push(i,l),e.push({inputUUID:(0,b.Z)(),interfaces:[null===(t=G[i])||void 0===t?void 0:t.metadata,null===(r=G[l])||void 0===r?void 0:r.metadata],ipAddress:o,isRequired:d,name:v,subnetMask:c,type:s,typeCount:f}),e}),[]);me(o),W((function(e){var n=_({},e);return a.forEach((function(e){n[e]&&(n[e].isApplied=!0)})),n})),ie(c),Re()}}),[u,Fe,l,G,S,Re]),(0,m.useEffect)((function(){return Pe(1),window&&window.addEventListener("beforeunload",(function(){var e=new XMLHttpRequest;e.open("PUT","".concat(g.Z,"/init/set-map-network"),!1),e.send(null)}),{once:!0}),function(){Pe(0)}}),[Pe]),(0,m.useImperativeHandle)(n,(function(){return _({},he.current,{get:function(){var e,n;return{dns:null===(e=be.current.getValue)||void 0===e?void 0:e.call(null),gateway:null===(n=ge.current.getValue)||void 0===n?void 0:n.call(null),gatewayInterface:pe,networks:oe.map((function(e){var n,t,r=e.inputUUID,o=e.interfaces,i=e.ipAddressInputRef,u=e.name,a=e.subnetMaskInputRef,l=e.type,c=e.typeCount;return{inputUUID:r,interfaces:o,ipAddress:null!==(C=null===(n=null===i||void 0===i?void 0:i.current.getValue)||void 0===n?void 0:n.call(null))&&void 0!==C?C:"",name:u,subnetMask:null!==(O=null===(t=null===a||void 0===a?void 0:a.current.getValue)||void 0===t?void 0:t.call(null))&&void 0!==O?O:"",type:l,typeCount:c}}))}}})}),[pe,oe]);var $e,Je="13em";return Ie?(0,r.jsx)(L.Z,{}):(0,r.jsxs)(o.Z,{onMouseDown:function(e){var n=e.clientX,t=e.clientY,r=e.currentTarget.getBoundingClientRect(),o=r.left,i=r.top;F({x:n-o,y:t-i})},onMouseLeave:Be,onMouseMove:_e,onMouseUp:Ge,sx:_({position:"relative"},qe),children:[He,(0,r.jsxs)(o.Z,{sx:{display:"flex",flexDirection:"column","& > :not(:first-child, :nth-child(3))":{marginTop:"1em"}},children:[(0,r.jsx)(d._,{autoHeight:!0,columns:le((function(e){de(e)}),G),componentsProps:{row:{onMouseDown:function(e){var n=e.target,t=(void 0===n?{}:n).parentElement,r=(void 0===t?{}:t).dataset,o=(void 0===r?{}:r).id,i=void 0===o?void 0:o;if(i){var u=G[i],a=u.isApplied,l=u.metadata;a||de(l)}}}},disableColumnMenu:!0,disableSelectionOnClick:!0,getRowClassName:function(e){var n,t=e.row.networkInterfaceUUID,r="";return(null!==(n=G[t])&&void 0!==n&&n).isApplied||(r+=" ".concat(X.ifaceNotApplied)),r},getRowId:function(e){return e.networkInterfaceUUID},hideFooter:!0,initialState:{sorting:{sortModel:[{field:"networkInterfaceName",sort:"asc"}]}},rows:xe,sx:($e={color:y.s7},B($e,"& .".concat(a.Z.root),{color:"inherit"}),B($e,"& .".concat(v._.cell,":focus"),{outline:"none"}),B($e,"& .".concat(v._.row,".").concat(X.ifaceNotApplied,":hover"),B({cursor:"grab"},"& .".concat(v._.cell," p"),{cursor:"auto"})),$e)}),!Ce&&(0,r.jsx)(D.Z,{row:!0,sx:{"& > :first-child":{alignSelf:"start",marginTop:".7em"},"& > :last-child":{flexGrow:1}},children:(0,r.jsx)(o.Z,{sx:{alignItems:"strech",display:"flex",flexDirection:"row",overflowX:"auto",paddingLeft:".3em","& > div":{marginBottom:".8em",marginTop:".4em",minWidth:Je,width:"25%"},"& > :not(:first-child)":{marginLeft:"1em"}},children:oe.map((function(e,n){var o=e.inputUUID;return(0,r.jsx)(ce,{allowMigrationNetwork:Oe,createDropMouseUpHandler:Le,getNetworkTypeCount:Fe,hostDetail:{hostType:t,sequence:I},networkIndex:n,networkInput:e,networkInterfaceCount:xe.length,networkInterfaceInputMap:G,removeNetwork:Ve,setMessageRe:Se,setNetworkInputs:ie,setNetworkInterfaceInputMap:W,testInput:Ne,testInputToToggleSubmitDisabled:Re},"network-".concat(o))}))})}),(0,r.jsxs)(D.Z,{sm:"row",sx:{marginTop:".2em","& > :not(button)":{minWidth:Je,width:{sm:"25%"}}},children:[(0,r.jsx)(A.Z,{disabled:je,onClick:function(){Te()},children:(0,r.jsx)(f.Z,{})}),(0,r.jsx)(N.Z,{input:(0,r.jsx)(E.Z,{id:"network-init-gateway",inputProps:{onBlur:function(e){var n=e.target.value;Ne({inputs:B({},Y,{value:n})})}},inputLabelProps:{isNotifyRequired:!0},onChange:function(e){var n=e.target.value;Re({inputs:B({},Y,{value:n})}),Ze()},label:"Gateway"}),ref:ge}),(0,r.jsx)(N.Z,{input:(0,r.jsx)(E.Z,{id:"network-init-dns-csv",inputProps:{onBlur:function(e){var n=e.target.value;Ne({inputs:B({},K,{value:n})})}},inputLabelProps:{isNotifyRequired:!0},onChange:function(e){var n=e.target.value;Re({inputs:B({},K,{value:n})}),Ue()},label:"Domain name server(s)"}),ref:be})]}),(0,r.jsx)(R.Z,{count:1,defaultMessageType:"warning",ref:he})]})]})}));se.defaultProps={expectHostDetail:!1,hostDetail:void 0,hostSequence:void 0,toggleSubmitDisabled:void 0},se.displayName="NetworkInitForm";var fe=se},3106:function(e,n){n.Z={bcn:"Back-Channel Network",ifn:"Internet-Facing Network",mn:"Migration Network",sn:"Storage Network"}}}]);