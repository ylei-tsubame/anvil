(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[249],{88668:function(e,n,t){var r=t(83369),i=t(90619),l=t(72385);function a(e){var n=-1,t=null==e?0:e.length;for(this.__data__=new r;++n<t;)this.add(e[n])}a.prototype.add=a.prototype.push=i,a.prototype.has=l,e.exports=a},82908:function(e){e.exports=function(e,n){for(var t=-1,r=null==e?0:e.length;++t<r;)if(n(e[t],t,e))return!0;return!1}},90939:function(e,n,t){var r=t(2492),i=t(37005);e.exports=function e(n,t,l,a,o){return n===t||(null!=n&&null!=t&&(i(n)||i(t))?r(n,t,l,a,e,o):n!=n&&t!=t)}},2492:function(e,n,t){var r=t(46384),i=t(67114),l=t(18351),a=t(16096),o=t(64160),s=t(1469),d=t(44144),c=t(36719),u="[object Arguments]",m="[object Array]",h="[object Object]",p=Object.prototype.hasOwnProperty;e.exports=function(e,n,t,g,f,v){var x=s(e),j=s(n),Z=x?m:o(e),b=j?m:o(n);Z=Z==u?h:Z,b=b==u?h:b;var y=Z==h,w=b==h,A=Z==b;if(A&&d(e)){if(!d(n))return!1;x=!0,y=!1}if(A&&!y)return v||(v=new r),x||c(e)?i(e,n,t,g,f,v):l(e,n,Z,t,g,f,v);if(!(1&t)){var C=y&&p.call(e,"__wrapped__"),_=w&&p.call(n,"__wrapped__");if(C||_){var O=C?e.value():e,P=_?n.value():n;return v||(v=new r),f(O,P,t,g,v)}}return!!A&&(v||(v=new r),a(e,n,t,g,f,v))}},74757:function(e){e.exports=function(e,n){return e.has(n)}},67114:function(e,n,t){var r=t(88668),i=t(82908),l=t(74757);e.exports=function(e,n,t,a,o,s){var d=1&t,c=e.length,u=n.length;if(c!=u&&!(d&&u>c))return!1;var m=s.get(e),h=s.get(n);if(m&&h)return m==n&&h==e;var p=-1,g=!0,f=2&t?new r:void 0;for(s.set(e,n),s.set(n,e);++p<c;){var v=e[p],x=n[p];if(a)var j=d?a(x,v,p,n,e,s):a(v,x,p,e,n,s);if(void 0!==j){if(j)continue;g=!1;break}if(f){if(!i(n,function(e,n){if(!l(f,n)&&(v===e||o(v,e,t,a,s)))return f.push(n)})){g=!1;break}}else if(!(v===x||o(v,x,t,a,s))){g=!1;break}}return s.delete(e),s.delete(n),g}},18351:function(e,n,t){var r=t(62705),i=t(11149),l=t(77813),a=t(67114),o=t(68776),s=t(21814),d=r?r.prototype:void 0,c=d?d.valueOf:void 0;e.exports=function(e,n,t,r,d,u,m){switch(t){case"[object DataView]":if(e.byteLength!=n.byteLength||e.byteOffset!=n.byteOffset)break;e=e.buffer,n=n.buffer;case"[object ArrayBuffer]":if(e.byteLength!=n.byteLength||!u(new i(e),new i(n)))break;return!0;case"[object Boolean]":case"[object Date]":case"[object Number]":return l(+e,+n);case"[object Error]":return e.name==n.name&&e.message==n.message;case"[object RegExp]":case"[object String]":return e==n+"";case"[object Map]":var h=o;case"[object Set]":var p=1&r;if(h||(h=s),e.size!=n.size&&!p)break;var g=m.get(e);if(g)return g==n;r|=2,m.set(e,n);var f=a(h(e),h(n),r,d,u,m);return m.delete(e),f;case"[object Symbol]":if(c)return c.call(e)==c.call(n)}return!1}},16096:function(e,n,t){var r=t(58234),i=Object.prototype.hasOwnProperty;e.exports=function(e,n,t,l,a,o){var s=1&t,d=r(e),c=d.length;if(c!=r(n).length&&!s)return!1;for(var u=c;u--;){var m=d[u];if(!(s?m in n:i.call(n,m)))return!1}var h=o.get(e),p=o.get(n);if(h&&p)return h==n&&p==e;var g=!0;o.set(e,n),o.set(n,e);for(var f=s;++u<c;){var v=e[m=d[u]],x=n[m];if(l)var j=s?l(x,v,m,n,e,o):l(v,x,m,e,n,o);if(!(void 0===j?v===x||a(v,x,t,l,o):j)){g=!1;break}f||(f="constructor"==m)}if(g&&!f){var Z=e.constructor,b=n.constructor;Z!=b&&"constructor"in e&&"constructor"in n&&!("function"==typeof Z&&Z instanceof Z&&"function"==typeof b&&b instanceof b)&&(g=!1)}return o.delete(e),o.delete(n),g}},68776:function(e){e.exports=function(e){var n=-1,t=Array(e.size);return e.forEach(function(e,r){t[++n]=[r,e]}),t}},90619:function(e){e.exports=function(e){return this.__data__.set(e,"__lodash_hash_undefined__"),this}},72385:function(e){e.exports=function(e){return this.__data__.has(e)}},21814:function(e){e.exports=function(e){var n=-1,t=Array(e.size);return e.forEach(function(e){t[++n]=e}),t}},18446:function(e,n,t){var r=t(90939);e.exports=function(e,n){return r(e,n)}},24084:function(e,n,t){(window.__NEXT_P=window.__NEXT_P||[]).push(["/mail-config",function(){return t(86901)}])},96674:function(e,n,t){"use strict";var r=t(85893),i=t(89256),l=t(62191),a=t(89262),o=t(59879),s=t(324),d=t(28721),c=t(73315),u=t(14440),m=t(55074),h=t(67294),p=t(77831),g=t(34635),f=t(91029);let v=e=>(0,r.jsx)(i.Z,{in:!0,children:(0,r.jsx)(l.Z,{...e})}),x=(0,a.ZP)("ul")({padding:0}),j=o.Z;n.Z=e=>{let{componentsProps:n,extendRenderInput:t,getGroupLabel:i,label:l,messageBoxProps:a,renderGroup:o,renderInput:Z,sx:b,...y}=e,w=(0,h.useMemo)(()=>({paper:{sx:{backgroundColor:p.lD,["& .".concat(s.Z.groupLabel)]:{backgroundColor:p.lD}}},...n}),[n]),A=(0,h.useMemo)(()=>o||i&&(e=>(0,r.jsxs)("li",{children:[(0,r.jsx)(j,{component:"div",className:s.Z.groupLabel,children:i(e.group)}),(0,r.jsx)(x,{className:s.Z.groupUl,children:e.children})]},e.key)),[i,o]),C=(0,h.useMemo)(()=>null!=Z?Z:e=>{let{fullWidth:n,InputProps:i,InputLabelProps:a,inputProps:o}=e,s={formControlProps:{fullWidth:n,ref:i.ref},inputLabelProps:a,inputProps:{className:i.className,endAdornment:i.endAdornment,inputProps:o,startAdornment:i.startAdornment},label:l};return null==t||t.call(null,s,e),(0,r.jsx)(f.Z,{...s})},[t,l,Z]),_=(0,h.useMemo)(()=>({["& .".concat(d.Z.root," .").concat(s.Z.endAdornment)]:{right:"7px",["& .".concat(c.Z.root)]:{color:p.s7}},...b}),[b]);return(0,r.jsxs)(u.Z,{sx:{display:"flex",flexDirection:"column"},children:[(0,r.jsx)(m.Z,{PaperComponent:v,...y,componentsProps:w,renderGroup:A,renderInput:C,sx:_}),(0,r.jsx)(g.Z,{...a})]})}},78533:function(e,n,t){"use strict";var r=t(85893),i=t(67294),l=t(98484),a=t(33544),o=t(97607),s=t(83916),d=t(68805),c=t(85291),u=t(2188),m=t(77510);let h=function(e){for(var n=arguments.length,t=Array(n>1?n-1:0),r=1;r<n;r++)t[r-1]=arguments[r];return"function"==typeof e?e(...t):e};n.Z=function(){for(var e=arguments.length,n=Array(e),t=0;t<e;t++)n[t]=arguments[t];let[p]=n,{addHeader:g,editHeader:f,entriesUrl:v,getAddLoading:x,getDeleteErrorMessage:j,getDeleteHeader:Z,getDeletePromiseChain:b=function(e){for(var n=arguments.length,t=Array(n>1?n-1:0),r=1;r<n;r++)t[r-1]=arguments[r];return e(...t)},getDeleteSuccessMessage:y,getEditLoading:w=e=>e,listEmpty:A,listProps:C,onItemClick:_=function(e){for(var n=arguments.length,t=Array(n>1?n-1:0),r=1;r<n;r++)t[r-1]=arguments[r];return e(...t)},refreshInterval:O=5e3,renderAddForm:P,renderDeleteItem:M,renderEditForm:k,renderListItem:F,entryUrlPrefix:S=v}=p,I=(0,i.useRef)(null),D=(0,i.useRef)(null),{confirmDialog:E,finishConfirm:V,setConfirmDialogLoading:R,setConfirmDialogOpen:U,setConfirmDialogProps:L}=(0,u.Z)({initial:{scrollContent:!0}}),[N,q]=(0,i.useState)(!1),[T,B]=(0,i.useState)(),{data:H,mutate:W,loading:z}=(0,m.Z)(v,{refreshInterval:O}),{fetch:K,loading:G}=(0,d.Z)({onData:e=>B(e),url:S}),J=(0,i.useMemo)(()=>h(g),[g]),X=(0,i.useMemo)(()=>h(f,T),[T,f]),Q=(0,i.useMemo)(()=>({add:{open:function(){var e;let n=!(arguments.length>0)||void 0===arguments[0]||arguments[0];return null==I?void 0:null===(e=I.current)||void 0===e?void 0:e.setOpen(n)}},confirm:{finish:V,loading:R,open:function(){let e=!(arguments.length>0)||void 0===arguments[0]||arguments[0];return U(e)},prepare:L},edit:{open:function(){var e;let n=!(arguments.length>0)||void 0===arguments[0]||arguments[0];return null==D?void 0:null===(e=D.current)||void 0===e?void 0:e.setOpen(n)}}}),[V,R,U,L]),{buildDeleteDialogProps:Y,checks:$,getCheck:ee,hasAllChecks:en,hasChecks:et,multipleItems:er,resetChecks:ei,setAllChecks:el,setCheck:ea}=(0,c.Z)({list:H});return(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(s.Z,{allowCheckAll:er,allowEdit:!0,allowItemButton:N,disableDelete:!et,edit:N,getListCheckboxProps:()=>({checked:en,onChange:(e,n)=>el(n)}),getListItemCheckboxProps:e=>({checked:ee(e),onChange:(n,t)=>ea(e,t)}),header:!0,listEmpty:A,listItems:H,loading:z,onAdd:()=>{var e;return null==I?void 0:null===(e=I.current)||void 0===e?void 0:e.setOpen(!0)},onDelete:()=>{L(Y({onProceedAppend:()=>{R(!0),Promise.all(b((e,n)=>e.map(e=>l.Z.delete("".concat(n,"/").concat(e))),$,v)).then(()=>{V("Success",y()),W()}).catch(e=>{V("Error",j((0,o.Z)(e)))}).finally(()=>{ei()})},getConfirmDialogTitle:Z,renderEntry:function(){for(var e=arguments.length,n=Array(e),t=0;t<e;t++)n[t]=arguments[t];return M(H,...n)}})),U(!0)},onEdit:()=>q(e=>!e),onItemClick:function(){for(var e=arguments.length,n=Array(e),t=0;t<e;t++)n[t]=arguments[t];return _((e,n)=>{var t;null==D||null===(t=D.current)||void 0===t||t.setOpen(!0),K("/".concat(n))},...n)},renderListItem:F,...C}),(0,r.jsx)(a.Js,{header:J,loading:null==x?void 0:x.call(null),ref:I,showClose:!0,children:P(Q)}),(0,r.jsx)(a.Js,{header:X,loading:w(G),ref:D,showClose:!0,children:k(Q,T)}),E]})}},39937:function(e,n,t){"use strict";t.d(n,{Z:function(){return E}});var r=t(85893),i=t(19338),l=t(89262),a=t(32653),o=t(14440),s=t(34815),d=t(80594),c=t(67294),u=t(77831),m=t(55278),h=t(26076),p=t(8489),g=t(37969),f=t(54965),v=t(49520);let x=[{text:"Anvil",image:"/pngs/anvil_icon_on.png",uri:"/manage-element"},{text:"Files",image:"/pngs/files_on.png",uri:"/file-manager"},{text:"Configure",image:"/pngs/configure_icon_on.png",uri:"/config"},{text:"Mail",image:"/pngs/email_on.png",uri:"/mail-config"},{text:"Help",image:"/pngs/help_icon_on.png",uri:"https://alteeve.com/w/Support"}],j={width:"40em",height:"40em"};var Z=t(98484),b=t(29535),y=t(56903),w=t(97607),A=t(59278),C=t(6946);let _="AnvilDrawer",O={actionIcon:"".concat(_,"-actionIcon"),list:"".concat(_,"-list")},P=(0,l.ZP)(p.ZP)(()=>({["& .".concat(O.list)]:{width:"200px"},["& .".concat(O.actionIcon)]:{fontSize:"2.3em",color:u.of}}));var M=e=>{let{open:n,setOpen:t}=e,{getSessionUser:i}=(0,C.Z)(),l=i();return(0,r.jsx)(P,{BackdropProps:{invisible:!0},anchor:"left",open:n,onClose:()=>t(!n),children:(0,r.jsx)("div",{role:"presentation",children:(0,r.jsxs)(g.Z,{className:O.list,children:[(0,r.jsx)(f.ZP,{children:(0,r.jsx)(A.Ac,{children:l?(0,r.jsxs)(r.Fragment,{children:["Welcome, ",l.name]}):"Unregistered"})}),(0,r.jsx)(b.Z,{}),(0,r.jsx)(v.Z,{component:"a",href:"/index.html",children:(0,r.jsxs)(y.Z,{fullWidth:!0,row:!0,spacing:"2em",children:[(0,r.jsx)(m.Z,{className:O.actionIcon}),(0,r.jsx)(A.Ac,{children:"Dashboard"})]})}),x.map(e=>(0,r.jsx)(v.Z,{component:"a",href:e.uri,children:(0,r.jsxs)(y.Z,{fullWidth:!0,row:!0,spacing:"2em",children:[(0,r.jsx)("img",{alt:e.text,src:e.image,...j}),(0,r.jsx)(A.Ac,{children:e.text})]})},"anvil-drawer-".concat(e.image))),(0,r.jsx)(v.Z,{onClick:()=>{Z.Z.put("/auth/logout").then(()=>{window.location.replace("/login")}).catch(e=>{(0,w.Z)(e)})},children:(0,r.jsxs)(y.Z,{fullWidth:!0,row:!0,spacing:"2em",children:[(0,r.jsx)(h.Z,{className:O.actionIcon}),(0,r.jsx)(A.Ac,{children:"Logout"})]})})]})})})},k=t(85838),F=t(39333);let S="Header",I={input:"".concat(S,"-input"),barElement:"".concat(S,"-barElement"),iconBox:"".concat(S,"-iconBox"),searchBar:"".concat(S,"-searchBar"),icons:"".concat(S,"-icons")},D=(0,l.ZP)(a.Z)(e=>{let{theme:n}=e;return{paddingTop:n.spacing(.5),paddingBottom:n.spacing(.5),paddingLeft:n.spacing(3),paddingRight:n.spacing(3),borderBottom:"solid 1px",borderBottomColor:u.hM,position:"static",["& .".concat(I.input)]:{height:"2.8em",width:"30vw",backgroundColor:n.palette.secondary.main,borderRadius:u.n_},["& .".concat(I.barElement)]:{padding:0},["& .".concat(I.iconBox)]:{[n.breakpoints.down("sm")]:{display:"none"}},["& .".concat(I.searchBar)]:{[n.breakpoints.down("sm")]:{flexGrow:1,paddingLeft:"15vw"}},["& .".concat(I.icons)]:{paddingLeft:".1em",paddingRight:".1em"}}});var E=()=>{let e=(0,c.useRef)({}),n=(0,c.useRef)({}),[t,l]=(0,c.useState)(!1);return(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(D,{children:(0,r.jsxs)(o.Z,{display:"flex",justifyContent:"space-between",flexDirection:"row",children:[(0,r.jsx)(y.Z,{row:!0,children:(0,r.jsx)(s.Z,{onClick:()=>l(!t),children:(0,r.jsx)("img",{alt:"",src:"/pngs/logo.png",width:"160",height:"40"})})}),(0,r.jsx)(y.Z,{className:I.iconBox,row:!0,spacing:0,children:(0,r.jsx)(o.Z,{children:(0,r.jsx)(d.Z,{onClick:e=>{var t,r;let{currentTarget:i}=e;null===(t=n.current.setAnchor)||void 0===t||t.call(null,i),null===(r=n.current.setOpen)||void 0===r||r.call(null,!0)},sx:{color:u.of,padding:"0 .1rem"},children:(0,r.jsx)(k.Z,{icon:i.Z,ref:e})})})})]})}),(0,r.jsx)(M,{open:t,setOpen:l}),(0,r.jsx)(F.Z,{onFetchSuccessAppend:n=>{var t;null===(t=e.current.indicate)||void 0===t||t.call(null,Object.keys(n).length>0)},ref:n})]})}},2188:function(e,n,t){"use strict";var r=t(85893),i=t(67294),l=t(77583),a=t(99576);n.Z=function(){let e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},{initial:{actionProceedText:n="",content:t="",titleText:o="",...s}={}}=e,d=(0,i.useRef)(null),[c,u]=(0,i.useState)({actionProceedText:n,content:t,titleText:o}),m=(0,i.useCallback)(e=>u(n=>{let{loading:t,...r}=n;return{...r,loading:e}}),[]),h=(0,i.useCallback)(e=>{var n,t;return null==d?void 0:null===(t=d.current)||void 0===t?void 0:null===(n=t.setOpen)||void 0===n?void 0:n.call(null,e)},[]),p=(0,i.useCallback)((e,n)=>u({actionProceedText:"",content:(0,r.jsx)(a.Z,{...n}),showActionArea:!1,showClose:!0,titleText:e}),[]);return{confirmDialog:(0,i.useMemo)(()=>(0,r.jsx)(l.Z,{...s,...c,ref:d}),[c,s]),confirmDialogRef:d,setConfirmDialogLoading:m,setConfirmDialogOpen:h,setConfirmDialogProps:u,finishConfirm:p}}},82547:function(e,n,t){"use strict";t.d(n,{Z:function(){return p}});var r=t(55066),i=t(18446),l=t.n(i),a=t(13218),o=t.n(a),s=t(67294),d=t(23279),c=t.n(d),u=function(e){let n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},{wait:t=500,...r}=n;return c()(e,t,r)},m=t(87196);let h=(e,n,t)=>{let[r,...i]=e;if(!(r in n))return!1;let a=n[r],s=t[r];return o()(a)&&o()(s)&&i.length?h(i,a,s):!l()(a,s)};var p=e=>{let[n,t]=(0,s.useState)(!1),i=(0,r.TA)({...e}),l=(0,s.useCallback)(e=>h(e.split("."),i.values,i.initialValues),[i.initialValues,i.values]),a=(0,s.useMemo)(()=>{let e=u(function(){for(var e=arguments.length,n=Array(e),r=0;r<e;r++)n[r]=arguments[r];i.handleChange(...n),t(!1)});return function(){for(var n=arguments.length,r=Array(n),i=0;i<n;i++)r[i]=arguments[i];t(!0),e(...r)}},[i.handleChange]),o=(0,s.useMemo)(()=>n||!i.dirty||!i.isValid||i.isValidating||i.isSubmitting,[n,i.dirty,i.isSubmitting,i.isValid,i.isValidating]),d=(0,s.useMemo)(()=>(0,m.Z)(i.errors,{skip:e=>!l(e)}),[i.errors,l]);return{disabledSubmit:o,formik:i,formikErrors:d,handleChange:a}}},59752:function(e,n,t){"use strict";t.d(n,{Z:function(){return i}});var r=e=>e.reduce((e,n)=>{let{hostName:t,hostType:r,hostUUID:i}=n;return e[i]={name:t,type:r,uuid:i},e},{}),i=e=>e.reduce((e,n)=>{let{anvilDescription:t,anvilName:i,anvilUUID:l,hosts:a}=n;return e[l]={description:t,hosts:r(a),name:i,uuid:l},e},{})},36026:function(e,n){"use strict";n.Z=(e,n)=>e&&Object.keys(e).reduce((e,t)=>({...e,[t]:n}),{})},86901:function(e,n,t){"use strict";t.r(n),t.d(n,{default:function(){return Q}});var r=t(85893),i=t(99514),l=t(9008),a=t.n(l),o=t(39937),s=t(60166),d=t(67294),c=t(25934),u=t(4845),m=t(98484),h=t(56903),p=t(44089),g=t(97607),f=t(16310),v=t(36026);let x=f.Rx().oneOf([0,1,2,3,4]),j=f.Ry({delete:f.O7().optional(),level:x.required(),target:f.Ry({type:f.Z_().oneOf(["node","subnode"]).required(),uuid:f.Z_().uuid().required()}),uuid:f.Z_().uuid().optional()}),Z=f.Vo(e=>f.Ry((0,v.Z)(e,j))),b=f.Ry({alertOverrides:Z,email:f.Z_().email().required(),language:f.Z_().oneOf(["en_CA"]).optional(),level:x.required(),name:f.Z_().required(),uuid:f.Z_().uuid().optional()}),y=f.Vo(e=>f.Ry((0,v.Z)(e,b)));var w=t(96674),A=t(65895),C=t(6189),_=t(59278),O=t(12387);let P=[{displayValue:"Ignore",value:0},{displayValue:"Critical",value:1},{displayValue:"Warning",value:2},{displayValue:"Notice",value:3},{displayValue:"Info",value:4}];var M=e=>{let{alertOverrideTargetOptions:n,alertOverrideValueId:t,mailRecipientUuid:l,formikUtils:a}=e,o=(0,d.useMemo)(()=>null!=t?t:(0,c.Z)(),[t]),{formik:s}=a,{values:{[l]:u}}=s,{alertOverrides:{[o]:m}}=u,p=(0,d.useMemo)(()=>"".concat(l,".alertOverrides.").concat(o),[o,l]),g=(0,d.useMemo)(()=>"".concat(p,".remove"),[p]),f=(0,d.useMemo)(()=>"".concat(p,".target"),[p]),v=(0,d.useMemo)(()=>"".concat(p,".level"),[p]);return(0,r.jsxs)(i.ZP,{alignItems:"center",columns:{xs:1,sm:10},container:!0,justifyContent:"stretch",spacing:"1em",children:[(0,r.jsx)(i.ZP,{item:!0,xs:6,children:(0,r.jsx)(w.Z,{getOptionLabel:e=>e.name,id:f,isOptionEqualToValue:(e,n)=>e.uuid===n.uuid,label:"Target",noOptionsText:"No node or subnode found.",onChange:(e,n)=>s.setFieldValue(f,n,!0),openOnFocus:!0,options:n,renderOption:(e,n)=>(0,d.createElement)("li",{...e,key:"".concat(n.node,"-").concat(n.uuid)},"node"===n.type?(0,r.jsxs)(h.Z,{spacing:0,children:[(0,r.jsx)(_.Ac,{inheritColour:!0,children:n.name}),(0,r.jsx)(_.KI,{inheritColour:!0,children:n.description})]}):(0,r.jsx)(_.Ac,{inheritColour:!0,paddingLeft:".6em",children:n.name})),value:m.target})}),(0,r.jsx)(i.ZP,{item:!0,flexGrow:1,children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(C.Z,{id:v,label:"Alert level",name:v,onChange:s.handleChange,selectItems:P,value:m.level})})}),(0,r.jsx)(i.ZP,{item:!0,width:"min-content",children:(0,r.jsx)(A.Z,{mapPreset:"delete",onClick:()=>{m.uuids?s.setFieldValue(g,!0,!0):s.setValues(e=>{let n={...e},{[l]:t}=n,{[o]:r,...i}=t.alertOverrides;return t.alertOverrides={...i},n})},size:"small"})})]})},k=t(83916),F=e=>{let{alertOverrideTargetOptions:n,formikUtils:t,mailRecipientUuid:i}=e,{formik:l}=t,{values:{[i]:a}}=l,{alertOverrides:o}=a;return(0,r.jsx)(k.Z,{allowAddItem:!0,edit:!0,header:"Alert override rules",listEmpty:"No alert overrides(s)",listItems:o,onAdd:()=>{let e=(0,c.Z)();l.setValues(n=>{let t={...n},{[i]:r}=t;return r.alertOverrides={...r.alertOverrides,[e]:{level:2,target:null}},t})},renderListItem:(e,l)=>!l.remove&&(0,r.jsx)(M,{alertOverrideTargetOptions:n,alertOverrideValueId:e,formikUtils:t,mailRecipientUuid:i})})},S=t(81208),I=t(91029),D=t(82547);let E=[{displayValue:(0,r.jsxs)(h.Z,{spacing:0,children:[(0,r.jsx)(_.Ac,{inheritColour:!0,fontWeight:"inherit",children:"Critical"}),(0,r.jsx)(_.KI,{inheritColour:!0,whiteSpace:"normal",children:"Alerts that could lead to imminent service interruption or unexpected loss of redundancy."})]}),value:1},{displayValue:(0,r.jsxs)(h.Z,{spacing:0,children:[(0,r.jsx)(_.Ac,{inheritColour:!0,fontWeight:"inherit",children:"Warning"}),(0,r.jsx)(_.KI,{inheritColour:!0,whiteSpace:"normal",children:"Alerts that require attention from administrators, such as redundancy loss due to load shedding, hardware in pre-failure, input power loss, temperature anomalies, etc."})]}),value:2},{displayValue:(0,r.jsxs)(h.Z,{spacing:0,children:[(0,r.jsx)(_.Ac,{inheritColour:!0,fontWeight:"inherit",children:"Notice"}),(0,r.jsx)(_.KI,{inheritColour:!0,whiteSpace:"normal",children:"Alerts that are generally safe to ignore, but might provide early warnings of developing issues or insight into system behaviour."})]}),value:3},{displayValue:(0,r.jsxs)(h.Z,{spacing:0,children:[(0,r.jsx)(_.Ac,{inheritColour:!0,fontWeight:"inherit",children:"Info"}),(0,r.jsx)(_.KI,{inheritColour:!0,whiteSpace:"normal",children:"Alerts that are almost always safe to ignore, but may be useful in testing and debugging."})]}),value:4}],V={1:"Critical",2:"Warning",3:"Notice",4:"Info"},R=function(e,n){let t=arguments.length>2&&void 0!==arguments[2]?arguments[2]:"/alert-override",{uuid:r}=e;return r?Object.values(e.alertOverrides).reduce((e,n)=>{let{remove:i,level:l,target:a,uuids:o}=n;if(o&&e.push(...Object.keys(o).map(e=>({method:"delete",url:"".concat(t,"/").concat(e)}))),a&&!i){var s;let n=null!==(s=a.subnodes)&&void 0!==s?s:[a.uuid];e.push(...n.map(e=>({body:{hostUuid:e,level:l,mailRecipientUuid:r},method:"post",url:t})))}return e},[]):[]};var U=e=>{let{alertOverrideTargetOptions:n,mailRecipientUuid:t,previousFormikValues:l,tools:a}=e,o=(0,d.useMemo)(()=>null!=t?t:(0,c.Z)(),[t]),h=(0,D.Z)({initialValues:null!=l?l:{[o]:{alertOverrides:{},email:"",language:"en_CA",level:2,name:""}},onSubmit:(e,n)=>{let{setSubmitting:t}=n,{[o]:i}=e,s="Add",d=(0,r.jsx)(r.Fragment,{children:"Failed to add mail recipient."}),c="post",u=(0,r.jsx)(r.Fragment,{children:"Mail recipient added."}),h="Add mail recipient with the following?",f="/mail-recipient";l&&(s="Update",d=(0,r.jsx)(r.Fragment,{children:"Failed to update mail server."}),c="put",u=(0,r.jsx)(r.Fragment,{children:"Mail recipient updated."}),h="Update ".concat(i.name," with the following?"),f+="/".concat(o));let{alertOverrides:v,uuid:x,...j}=i;a.confirm.prepare({actionProceedText:s,content:(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(p.Z,{entries:j}),(0,r.jsx)(p.Z,{entries:{alertOverrides:Object.entries(v).reduce((e,n)=>{let[t,r]=n;return r.remove||!r.target||(e[t]={level:r.level,name:r.target.name}),e},{})}})]}),onCancelAppend:()=>t(!1),onProceedAppend:async()=>{a.confirm.loading(!0);let e=e=>{let n=(0,g.Z)(e);n.children=(0,r.jsxs)(r.Fragment,{children:[d," ",n.children]}),a.confirm.finish("Error",n),t(!1)};m.Z[c](f,j).then(n=>{let{data:t}=n,r={...i};t&&(r.uuid=t.uuid),Promise.all(R(r,l&&l[o]).map(e=>m.Z[e.method](e.url,e.body))).then(()=>{a.confirm.finish("Success",{children:u}),a["post"===c?"add":"edit"].open(!1)}).catch(e)}).catch(e)},titleText:h}),a.confirm.open(!0)},validationSchema:y}),{disabledSubmit:f,formik:v,formikErrors:x,handleChange:j}=h,Z=(0,d.useMemo)(()=>"".concat(o,".email"),[o]),b=(0,d.useMemo)(()=>"".concat(o,".level"),[o]),w=(0,d.useMemo)(()=>"".concat(o,".name"),[o]);return(0,r.jsxs)(i.ZP,{columns:{xs:1,sm:2},component:"form",container:!0,onSubmit:e=>{e.preventDefault(),v.submitForm()},spacing:"1em",children:[(0,r.jsx)(i.ZP,{item:!0,xs:1,children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(I.Z,{id:w,label:"Recipient name",name:w,onChange:j,required:!0,value:v.values[o].name})})}),(0,r.jsx)(i.ZP,{item:!0,xs:1,children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(I.Z,{id:Z,label:"Recipient email",name:Z,onChange:j,required:!0,value:v.values[o].email})})}),(0,r.jsx)(i.ZP,{item:!0,xs:1,children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(C.Z,{id:b,label:"Alert level",name:b,onChange:v.handleChange,required:!0,selectItems:E,selectProps:{MenuProps:{sx:{["& .".concat(s.Z.paper)]:{maxWidth:{md:"60%",lg:"40%"}}}},renderValue:e=>V[e]},value:v.values[o].level})})}),(0,r.jsx)(i.ZP,{item:!0,width:"100%",children:(0,r.jsx)(F,{alertOverrideTargetOptions:n,formikUtils:h,mailRecipientUuid:o})}),(0,r.jsx)(i.ZP,{item:!0,width:"100%",children:(0,r.jsx)(S.Z,{count:1,messages:x})}),(0,r.jsx)(i.ZP,{item:!0,width:"100%",children:(0,r.jsx)(u.Z,{actions:[{background:"blue",children:l?"Update":"Add",disabled:f,type:"submit"}]})})]})},L=t(59752),N=t(78533),q=e=>(0,r.jsx)(U,{...e}),T=t(68805),B=t(77510),H=()=>{let[e,n]=(0,d.useState)(),{altData:t,loading:i}=(0,B.Z)("/anvil",{mod:L.Z}),l=(0,d.useMemo)(()=>t&&Object.values(t).sort((e,n)=>e.name.localeCompare(n.name)).reduce((e,n)=>{let t={description:n.description,name:n.name,node:n.uuid,subnodes:[],type:"node",uuid:n.uuid},r=Object.values(n.hosts).sort((e,n)=>e.name.localeCompare(n.name)).reduce((e,r)=>{var i;return"dr"===r.type||(e.push({name:r.name,node:n.uuid,type:"subnode",uuid:r.uuid}),null===(i=t.subnodes)||void 0===i||i.push(r.uuid)),e},[]);return e.push(t,...r),e},[]),[t]),{fetch:a,loading:o}=(0,T.Z)({onData:e=>n(e),url:"/alert-override"}),s=(0,d.useMemo)(()=>{if(t&&e)return Object.entries(Object.values(e).reduce((e,n)=>{let{node:{uuid:t}}=n;return e[t]?e[t].push(n):e[t]=[n],e},{})).reduce((e,n)=>{let[r,i]=n,[l,...a]=i;if(i.length>1&&a.every(e=>{let{level:n}=e;return n===l.level})){let{0:{level:n}}=i,{[r]:l}=t;e[r]={level:n,target:{description:l.description,name:l.name,node:l.uuid,subnodes:i.map(e=>{let{subnode:{uuid:n}}=e;return n}),type:"node",uuid:l.uuid},uuids:i.reduce((e,n)=>{let{subnode:t,uuid:r}=n;return e[r]=t.uuid,e},{})}}else i.forEach(n=>{let{level:t,node:r,subnode:i,uuid:l}=n;e[i.uuid]={level:t,target:{name:i.name,node:r.uuid,type:"subnode",uuid:i.uuid},uuids:{[l]:i.uuid}}});return e},{})},[e,t]);return(0,r.jsx)(r.Fragment,{children:(0,r.jsx)(N.Z,{addHeader:"Add mail recipient",editHeader:e=>"Update ".concat(null==e?void 0:e.name),entriesUrl:"/mail-recipient",getAddLoading:e=>e||i,getDeleteErrorMessage:e=>{let{children:n,...t}=e;return{...t,children:(0,r.jsxs)(r.Fragment,{children:["Failed to delete mail recipient(s). ",n]})}},getDeleteHeader:e=>"Delete the following ".concat(e," mail recipient(s)?"),getDeleteSuccessMessage:()=>({children:(0,r.jsx)(r.Fragment,{children:"Successfully deleted mail recipient(s)."})}),getEditLoading:e=>e||o,listEmpty:"No mail recipient(s) found.",onItemClick:function(e){for(var n=arguments.length,t=Array(n>1?n-1:0),r=1;r<n;r++)t[r-1]=arguments[r];let[,i]=t;e(...t),a(void 0,{params:{"mail-recipient":i}})},renderAddForm:e=>l&&(0,r.jsx)(U,{alertOverrideTargetOptions:l,tools:e}),renderDeleteItem:(e,n)=>{let{key:t}=n,i=null==e?void 0:e[t];return(0,r.jsx)(_.Ac,{children:null==i?void 0:i.name})},renderEditForm:(e,n)=>l&&n&&s&&(0,r.jsx)(q,{alertOverrideTargetOptions:l,mailRecipientUuid:n.uuid,previousFormikValues:{[n.uuid]:{alertOverrides:s,...n}},tools:e}),renderListItem:(e,n)=>{let{name:t}=n;return(0,r.jsx)(_.Ac,{children:t})}})})};let W=f.Ry({address:f.Z_().required(),authentication:f.Z_().oneOf(["none","plain-text","encrypted"]),confirmPassword:f.Z_().when("password",(e,n)=>String(e).length>0?n.required().oneOf([f.iH("password")]):n.optional()),heloDomain:f.Z_().required(),password:f.Z_().optional(),port:f.Rx().required(),security:f.Z_().oneOf(["none","starttls","tls-ssl"]),username:f.Z_().optional(),uuid:f.Z_().uuid().required()}),z=f.Vo(e=>f.Ry((0,v.Z)(e,W)));var K=e=>{let{localhostDomain:n="",mailServerUuid:t,previousFormikValues:l,tools:a}=e,o=(0,d.useMemo)(()=>null!=t?t:(0,c.Z)(),[t]),{disabledSubmit:s,formik:h,formikErrors:f,handleChange:v}=(0,D.Z)({initialValues:null!=l?l:{[o]:{address:"",authentication:"none",heloDomain:n,port:587,security:"none",uuid:o}},onSubmit:(e,n)=>{let{setSubmitting:t}=n,{[o]:i}=e,s="Add",d=(0,r.jsx)(r.Fragment,{children:"Failed to add mail server."}),c="post",u=(0,r.jsx)(r.Fragment,{children:"Mail server added."}),h="Add mail server with the following?",f="/mail-server";l&&(s="Update",d=(0,r.jsx)(r.Fragment,{children:"Failed to update mail server."}),c="put",u=(0,r.jsx)(r.Fragment,{children:"Mail server updated."}),h="Update ".concat(i.address,":").concat(i.port," with the following?"),f+="/".concat(o));let{confirmPassword:v,uuid:x,...j}=i;a.confirm.prepare({actionProceedText:s,content:(0,r.jsx)(p.Z,{entries:j}),onCancelAppend:()=>t(!1),onProceedAppend:()=>{a.confirm.loading(!0),m.Z[c](f,i).then(()=>{a.confirm.finish("Success",{children:u}),a["post"===c?"add":"edit"].open(!1)}).catch(e=>{let n=(0,g.Z)(e);n.children=(0,r.jsxs)(r.Fragment,{children:[d," ",n.children]}),a.confirm.finish("Error",n),t(!1)})},titleText:h}),a.confirm.open(!0)},validationSchema:z}),x=(0,d.useMemo)(()=>"".concat(o,".address"),[o]),j=(0,d.useMemo)(()=>"".concat(o,".authentication"),[o]),Z=(0,d.useMemo)(()=>"".concat(o,".confirmPassword"),[o]),b=(0,d.useMemo)(()=>"".concat(o,".heloDomain"),[o]),y=(0,d.useMemo)(()=>"".concat(o,".password"),[o]),w=(0,d.useMemo)(()=>"".concat(o,".port"),[o]),A=(0,d.useMemo)(()=>"".concat(o,".security"),[o]),_=(0,d.useMemo)(()=>"".concat(o,".username"),[o]);return(0,r.jsxs)(i.ZP,{component:"form",onSubmit:e=>{e.preventDefault(),h.submitForm()},container:!0,columns:{xs:1,sm:2},spacing:"1em",children:[(0,r.jsx)(i.ZP,{item:!0,xs:1,children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(I.Z,{id:x,label:"Server address",name:x,onChange:v,required:!0,value:h.values[o].address})})}),(0,r.jsx)(i.ZP,{item:!0,xs:1,children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(I.Z,{id:w,label:"Server port",name:w,onChange:v,required:!0,type:"number",value:h.values[o].port})})}),(0,r.jsx)(i.ZP,{item:!0,width:"100%",children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(C.Z,{id:A,label:"Server security type",name:A,onChange:v,required:!0,selectItems:["none","starttls","tls-ssl"],value:h.values[o].security})})}),(0,r.jsx)(i.ZP,{item:!0,width:"100%",children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(C.Z,{id:j,label:"Server authentication method",name:j,onChange:v,required:!0,selectItems:["none","plain-text","encrypted"],value:h.values[o].authentication})})}),(0,r.jsx)(i.ZP,{item:!0,width:"100%",children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(I.Z,{id:b,label:"HELO domain",name:b,onChange:v,required:!0,value:h.values[o].heloDomain})})}),(0,r.jsx)(i.ZP,{item:!0,xs:1,children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(I.Z,{disableAutofill:!0,id:_,label:"Server username",name:_,onChange:v,value:h.values[o].username})})}),(0,r.jsx)(i.ZP,{item:!0,xs:1,children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(I.Z,{disableAutofill:!0,id:y,label:"Server password",name:y,onChange:v,type:"password",value:h.values[o].password})})}),(0,r.jsx)(i.ZP,{display:{xs:"none",sm:"initial"},item:!0,sm:1}),(0,r.jsx)(i.ZP,{item:!0,xs:1,children:(0,r.jsx)(O.Z,{input:(0,r.jsx)(I.Z,{disableAutofill:!0,id:Z,label:"Confirm password",name:Z,onChange:v,type:"password",value:h.values[o].confirmPassword})})}),(0,r.jsx)(i.ZP,{item:!0,width:"100%",children:(0,r.jsx)(S.Z,{count:1,messages:f})}),(0,r.jsx)(i.ZP,{item:!0,width:"100%",children:(0,r.jsx)(u.Z,{actions:[{background:"blue",children:l?"Update":"Add",disabled:s,type:"submit"}]})})]})},G=e=>(0,r.jsx)(K,{...e}),J=()=>{let{data:e,loading:n}=(0,B.Z)("/host/local");return(0,r.jsx)(r.Fragment,{children:(0,r.jsx)(N.Z,{addHeader:"Add mail server",editHeader:e=>"Update ".concat(null==e?void 0:e.address,":").concat(null==e?void 0:e.port),entriesUrl:"/mail-server",getAddLoading:e=>e||n,getDeleteErrorMessage:e=>{let{children:n,...t}=e;return{...t,children:(0,r.jsxs)(r.Fragment,{children:["Failed to delete mail server(s). ",n]})}},getDeleteHeader:e=>"Delete the following ".concat(e," mail server(s)?"),getDeleteSuccessMessage:()=>({children:(0,r.jsx)(r.Fragment,{children:"Successfully deleted mail server(s)."})}),listEmpty:"No mail server(s) found",renderAddForm:n=>e&&(0,r.jsx)(K,{localhostDomain:e.domain,tools:n}),renderDeleteItem:(e,n)=>{let{key:t}=n,i=null==e?void 0:e[t];return(0,r.jsxs)(_.Ac,{children:[null==i?void 0:i.address,":",null==i?void 0:i.port]})},renderEditForm:(e,n)=>n&&(0,r.jsx)(G,{mailServerUuid:n.uuid,previousFormikValues:{[n.uuid]:n},tools:e}),renderListItem:(e,n)=>{let{address:t,port:i}=n;return(0,r.jsxs)(_.Ac,{children:[t,":",i]})}})})},X=t(23930),Q=()=>(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(a(),{children:(0,r.jsx)("title",{children:"Mail Config"})}),(0,r.jsx)(o.Z,{}),(0,r.jsxs)(i.ZP,{container:!0,columns:{xs:1,md:6,lg:4},children:[(0,r.jsx)(i.ZP,{item:!0,xs:1}),(0,r.jsx)(i.ZP,{item:!0,xs:1,md:4,lg:2,children:(0,r.jsxs)(X.s_,{children:[(0,r.jsx)(X.V9,{children:(0,r.jsx)(_.z,{children:"Mail config"})}),(0,r.jsx)(X.TZ,{expandInitially:!0,header:"Manage mail servers",children:(0,r.jsx)(J,{})}),(0,r.jsx)(X.TZ,{expandInitially:!0,header:"Manage mail recipients",children:(0,r.jsx)(H,{})})]})})]})]})}},function(e){e.O(0,[572,442,318,341,514,242,74,461,602,616,762,845,888,774,179],function(){return e(e.s=24084)}),_N_E=e.O()}]);