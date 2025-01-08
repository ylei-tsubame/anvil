"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[558],{42050:function(e,n,o){var r=o(85893),t=o(77527),l=o(67294),a=o(25934),i=o(46194),s=o(5387),c=o(90209);let u=(0,t.ZP)(s.Z)({justifyContent:"flex-end",width:"100%"});n.Z=e=>{let{actions:n=[],loading:o}=e,t=(0,l.useMemo)(()=>n.map(e=>(0,r.jsx)(i.Z,{...e,children:e.children},(0,a.Z)())),[n]);return o?(0,r.jsx)(c.Z,{mt:0}):(0,r.jsx)(u,{row:!0,spacing:".5em",children:t})}},21649:function(e,n,o){var r=o(77527),t=o(14959),l=o(45214),a=o(39971);let i=(0,r.ZP)(t.Z)({backgroundColor:"transparent",borderRadius:a.n_,height:"1em",["& .".concat(l.Z.bar)]:{borderRadius:a.n_}});n.Z=i},55507:function(e,n,o){var r=o(85893),t=o(77527),l=o(45214),a=o(90642),i=o(82492),s=o.n(i),c=o(67294),u=o(39971),d=o(21649),m=o(42947);let p=(0,t.ZP)(d.Z)({height:".4em"}),g=(0,t.ZP)(m.Z)({height:".2em"});n.Z=e=>{let{barProps:n,thin:o,underlineProps:t,value:i}=e,f=(0,c.useMemo)(()=>"value"in i?{default:i}:i,[i]),h=(0,c.useMemo)(()=>Object.entries(f).reverse(),[f]),x=(0,c.useMemo)(()=>o?p:d.Z,[o]),v=(0,c.useMemo)(()=>o?g:m.Z,[o]),Z=(0,c.useMemo)(()=>h.map((e,o)=>{var r,t;let a,i,[d,m]=e,{barProps:p,colour:g=u.s7,value:f}=m,h="string"==typeof g?g:null!==(t=null===(r=Object.entries(g).reverse().find(e=>{let[n]=e;return f>=Number(n)}))||void 0===r?void 0:r[1])&&void 0!==t?t:u.s7,v="relative";return o&&(v="absolute",a=0,i="100%"),(0,c.createElement)(x,s()({key:"stack-bar-".concat(d),sx:{position:v,top:a,width:i,["& .".concat(l.Z.bar)]:{backgroundColor:h}},variant:"determinate",value:f},n,p))}),[n,x,h]);return(0,r.jsxs)(a.Z,{position:"relative",children:[Z,(0,c.createElement)(v,t)]})}},42947:function(e,n,o){var r=o(77527),t=o(90642),l=o(39971);let a=(0,r.ZP)(t.Z)({backgroundColor:l.rr,borderRadius:l.n_,display:"block",height:"4px",position:"relative"});n.Z=a},41373:function(e,n,o){o.d(n,{CD:function(){return d},_1:function(){return x},ko:function(){return j},Tj:function(){return P}});var r=o(85893),t=o(77527),l=o(39971),a=o(21649),i=o(42947);let s="AllocationBar",c={barOk:"".concat(s,"-barOk"),barWarning:"".concat(s,"-barWarning"),barAlert:"".concat(s,"-barAlert")},u=(0,t.ZP)("div")(()=>({["& .".concat(c.barOk)]:{backgroundColor:l.Ej},["& .".concat(c.barWarning)]:{backgroundColor:l.Wd},["& .".concat(c.barAlert)]:{backgroundColor:l.hM}}));var d=e=>{let{allocated:n}=e;return(0,r.jsxs)(u,{children:[(0,r.jsx)(a.Z,{classes:{bar:n>70?n>90?c.barAlert:c.barWarning:c.barOk},variant:"determinate",value:n}),(0,r.jsx)(i.Z,{})]})},m=o(82492),p=o.n(m),g=o(67294),f=o(55507);let h=BigInt(100);var x=e=>{let{memory:n,value:o,...t}=e,{allocated:a,reserved:i,total:s}=n,c=(0,g.useMemo)(()=>{let e=Number((s-i)*h/s);return{0:l.Ej,[String(.7*e)]:l.Wd,[String(.9*e)]:l.hM}},[i,s]),u=(0,g.useMemo)(()=>p()({reserved:{barProps:{sx:{rotate:"180deg"}},value:Number(i*h/s)},allocated:{value:Number(a*h/s),colour:c}},o),[a,c,i,s,o]);return(0,r.jsx)(f.Z,{...t,value:u})};let v="ProgressBar",Z={barOk:"".concat(v,"-barOk"),barInProgress:"".concat(v,"-barInProgress")},b=(0,t.ZP)("div")(()=>({["& .".concat(Z.barOk)]:{backgroundColor:l.Ej},["& .".concat(Z.barInProgress)]:{backgroundColor:l.Wd}}));var j=e=>{let{progressPercentage:n}=e;return(0,r.jsxs)(b,{children:[(0,r.jsx)(a.Z,{classes:{bar:n<100?Z.barInProgress:Z.barOk},variant:"determinate",value:n}),(0,r.jsx)(i.Z,{})]})};let C=BigInt(100),y=e=>{let{storages:n,target:o,value:t,...a}=e,{totalSize:i,totalUsed:s}=n,c=(0,g.useMemo)(()=>{var e;if(!o)return;let r=null===(e=n.storageGroups)||void 0===e?void 0:e[o];if(r)return r},[o,n.storageGroups]),u=(0,g.useMemo)(()=>({0:l.Ej,70:l.Wd,90:l.hM}),[]),d=(0,g.useMemo)(()=>p()(c?{target:{value:Number(c.used*C/c.size),colour:u}}:{base:{value:Number(s*C/i),colour:u}},t),[s,u,c,i,t]);return(0,r.jsx)(f.Z,{...a,value:d})};y.defaultProps={target:void 0};var P=y},65902:function(e,n,o){var r=o(77527),t=o(27398),l=o(39971);let a=(0,r.ZP)(t.Z)({color:l.s7});n.Z=a},46194:function(e,n,o){o.d(n,{D:function(){return s}});var r=o(85893),t=o(77527),l=o(19929),a=o(30083),i=o(39971);let s={blue:i.Ej,normal:i.s7,red:i.hM},c=(0,t.ZP)(l.Z)({backgroundColor:i.s7,color:i.E5,textTransform:"none","&:hover":{backgroundColor:"".concat(i.s7,"F0")},["&.".concat(a.Z.disabled)]:{backgroundColor:i.rr}}),u=(0,t.ZP)(e=>(0,r.jsx)(c,{variant:"contained",...e}))(e=>{let n,o;let{background:r="normal"}=e;return"normal"!==r&&(n=s[r],o=i.lD),{backgroundColor:n,color:o,"&:hover":{backgroundColor:"".concat(n,"F0")}}});n.Z=u},45036:function(e,n,o){o.d(n,{ux:function(){return m},VZ:function(){return Z},Js:function(){return j}});var r=o(85893),t=o(32187),l=o(67294),a=o(65375),i=o(90209);let s=(0,l.createContext)(void 0),c=(0,l.forwardRef)((e,n)=>{let{children:o,dialogProps:c={},loading:u,openInitially:d=!1,wide:m}=e,{open:p,PaperProps:g={},...f}=c,{sx:h,...x}=g,[v,Z]=(0,l.useState)(d),b=(0,l.useMemo)(()=>null!=p?p:v,[v,p]),j=(0,l.useMemo)(()=>u?(0,r.jsx)(i.Z,{mt:0}):o,[o,u]),C=(0,l.useMemo)(()=>({minWidth:m?{xs:"calc(100%)",md:"50em"}:null,overflow:"visible",...h}),[h,m]);return(0,l.useImperativeHandle)(n,()=>({open:b,setOpen:Z}),[b]),(0,r.jsx)(t.Z,{open:b,PaperComponent:a.s_,PaperProps:{...x,sx:C},...f,children:(0,r.jsx)(s.Provider,{value:{open:b,setOpen:Z},children:j})})});c.displayName="Dialog";var u=o(42050);let d=function(e){let{handlers:{base:n,origin:o}}=e;for(var r=arguments.length,t=Array(r>1?r-1:0),l=1;l<r;l++)t[l-1]=arguments[l];null==n||n.call(null,...t),null==o||o.call(null,...t)};var m=e=>{let{cancelProps:n,closeOnProceed:o,loading:t=!1,onCancel:a=d,onProceed:i=d,proceedColour:c,proceedProps:m,showCancel:p=!0,cancelChildren:g=null==n?void 0:n.children,proceedChildren:f=null==m?void 0:m.children}=e,h=(0,l.useContext)(s),x=(0,l.useCallback)(function(){for(var e=arguments.length,o=Array(e),r=0;r<e;r++)o[r]=arguments[r];return a({handlers:{base:()=>{null==h||h.setOpen(!1)},origin:null==n?void 0:n.onClick}},...o)},[null==n?void 0:n.onClick,h,a]),v=(0,l.useCallback)(function(){for(var e=arguments.length,n=Array(e),r=0;r<e;r++)n[r]=arguments[r];return i({handlers:{base:()=>{o&&(null==h||h.setOpen(!1))},origin:null==m?void 0:m.onClick}},...n)},[o,h,i,null==m?void 0:m.onClick]);return(0,l.useMemo)(()=>{let e=[{background:c,...m,children:f,onClick:v}];return p&&e.unshift({...n,children:g,onClick:x}),(0,r.jsx)(u.Z,{actions:e,loading:t})},[g,x,n,t,f,c,v,m,p])},p=o(45328),g=o(71487),f=o(57882),h=e=>{let{children:n,onClose:o=function(e){let{handlers:{base:n}}=e;for(var o=arguments.length,r=Array(o>1?o-1:0),t=1;t<o;t++)r[t-1]=arguments[t];return null==n?void 0:n.call(null,...r)},showClose:t}=e,i=(0,l.useContext)(s),c=(0,l.useCallback)(function(){for(var e=arguments.length,n=Array(e),r=0;r<e;r++)n[r]=arguments[r];return o({handlers:{base:()=>{null==i||i.setOpen(!1)}}},...n)},[i,o]),u=(0,l.useMemo)(()=>(0,g.Z)(n,f.z),[n]),d=(0,l.useMemo)(()=>t&&(0,r.jsx)(p.Z,{mapPreset:"close",onClick:c,size:"small"}),[c,t]);return(0,r.jsxs)(a.V9,{children:[u,d]})},x=o(77527),v=o(28192),Z=(0,x.ZP)(v.Z)({maxHeight:"60vh"});let b=(0,l.forwardRef)((e,n)=>{let{children:o,dialogProps:t,header:l,loading:a,onClose:i,openInitially:s,showClose:u,wide:d}=e;return(0,r.jsxs)(c,{dialogProps:t,loading:a,openInitially:s,ref:n,wide:d,children:[(0,r.jsx)(h,{onClose:i,showClose:u,children:l}),o]})});b.displayName="DialogWithHeader";var j=b},5387:function(e,n,o){var r=o(85893),t=o(90642),l=o(67294);let a={columnSpacing:void 0,fullWidth:!1,growFirst:!1,row:!1,rowSpacing:void 0,lg:void 0,md:void 0,sm:void 0,spacing:"1em",xl:void 0,xs:"column"},i=e=>{let{fullWidth:n,growFirst:o,lg:i=a.lg,md:s=a.md,row:c,sm:u=a.sm,spacing:d=a.spacing,sx:m,xl:p=a.xl,xs:g=a.xs,columnSpacing:f=d,rowSpacing:h=d,...x}=e,v=(0,l.useMemo)(()=>c?"row":g,[g,c]),Z=(0,l.useMemo)(()=>u||v,[u,v]),b=(0,l.useMemo)(()=>s||Z,[s,Z]),j=(0,l.useMemo)(()=>i||b,[i,b]),C=(0,l.useMemo)(()=>p||j,[p,j]),y=(0,l.useMemo)(()=>({column:{alignItems:"normal",marginLeft:0,marginTop:f},row:{alignItems:"center",marginLeft:h,marginTop:0}}),[f,h]),P=(0,l.useMemo)(()=>o?1:void 0,[o]),k=(0,l.useMemo)(()=>n?"100%":void 0,[n]);return(0,r.jsx)(t.Z,{...x,sx:{alignItems:{xs:y[v].alignItems,sm:y[Z].alignItems,md:y[b].alignItems,lg:y[j].alignItems,xl:y[C].alignItems},display:"flex",flexDirection:{xs:v,sm:Z,md:b,lg:j,xl:C},width:k,"& > :first-child":{flexGrow:P},"& > :not(:first-child)":{marginLeft:{xs:y[v].marginLeft,sm:y[Z].marginLeft,md:y[b].marginLeft,lg:y[j].marginLeft,xl:y[C].marginLeft},marginTop:{xs:y[v].marginTop,sm:y[Z].marginTop,md:y[b].marginTop,lg:y[j].marginTop,xl:y[C].marginTop}},...m}})};i.defaultProps=a,n.Z=i},16667:function(e,n,o){var r=o(53839),t=o(38444),l=o(23811),a=o(89090),i=o(17071),s=o(43562),c=o(22274),u=o(9122),d=o(47698),m=o(77527),p=o(7727),g=o(8499),f=o(67294),h=o(39971);let x=(0,m.ZP)(p.Z)({borderRadius:h.n_,backgroundColor:h.s7,color:h.E5,"&:hover":{backgroundColor:"".concat(h.s7,"F0")},["&.".concat(g.Z.disabled)]:{backgroundColor:h.rr}}),v=(0,m.ZP)(x)({backgroundColor:h.hM,color:h.s7,"&:hover":{backgroundColor:"".concat(h.hM,"F0")}}),Z=(0,m.ZP)(p.Z)({color:h.s7}),b={none:{iconType:r.Z}},j={none:{iconType:t.Z}},C={none:{iconType:l.Z}},y={none:{iconType:a.Z}},P={add:b,close:j,copy:C,delete:y,edit:{false:{iconType:i.Z},true:{iconType:s.Z,iconProps:{sx:{color:h.Ej}}}},play:{none:{iconType:c.Z}},visibility:{false:{iconType:u.Z},true:{iconType:d.Z}}},k={contained:x,normal:Z,redcontained:v};n.Z=e=>{let{children:n,defaultIcon:o,iconProps:r,mapPreset:t,mapToIcon:l,state:a="none",variant:i="contained",...s}=e,c=(0,f.useMemo)(()=>null!=l?l:t&&P[t],[l,t]),u=(0,f.useMemo)(()=>{let e;if(c){var t;let{iconType:n,iconProps:l}=null!==(t=c[a])&&void 0!==t?t:{iconType:o};n&&(e=(0,f.createElement)(n,{...l,...r}))}else e=n;return e},[n,o,r,c,a]),d=(0,f.useMemo)(()=>k[i],[i]);return(0,f.createElement)(d,s,u)}},45328:function(e,n,o){var r=o(16667);n.Z=r.Z},17512:function(e,n,o){var r=o(85893),t=o(29873);n.Z=function(){let{sx:e,text:n,...o}=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{};return(0,r.jsx)(r.Fragment,{children:n&&(0,r.jsx)(t.Z,{...o,sx:{marginTop:".4em",...e},text:n})})}},29873:function(e,n,o){var r=o(85893),t=o(67294),l=o(90642),a=o(7727),i=o(43656),s=o(31925),c=o(90691),u=o(38444),d=o(39971),m=o(57882);let p="MessageBox",g={error:"".concat(p,"-error"),info:"".concat(p,"-info"),warning:"".concat(p,"-warning")},f={error:(0,r.jsx)(i.Z,{}),info:(0,r.jsx)(s.Z,{}),warning:(0,r.jsx)(c.Z,{})},h={isShowInitially:!0,isAllowClose:!1,onClose:void 0,onCloseAppend:void 0,text:void 0,type:"info"},x=e=>{let{children:n,isAllowClose:o=h.isAllowClose,isShowInitially:i=h.isShowInitially,onClose:s,onCloseAppend:c,type:p=h.type,text:x,...v}=e,{sx:Z}=v,[b,j]=(0,t.useState)(i),C=(0,t.useMemo)(()=>o||void 0!==s||void 0!==c,[o,s,c]),y=(0,t.useCallback)(e=>g[e],[]),P=(0,t.useCallback)(e=>void 0===f[e]?f.info:f[e],[]),k=(0,t.useCallback)(function(e){let o=arguments.length>1&&void 0!==arguments[1]?arguments[1]:n;return(0,r.jsx)(m.Ac,{inverted:"info"===e,children:o})},[n]),w=(0,t.useMemo)(()=>({alignItems:"center",borderRadius:d.n_,display:"flex",flexDirection:"row",padding:".3em .6em","& > *":{color:d.lD},"& > :first-child":{marginRight:".3em"},"& > :nth-child(2)":{flexGrow:1},["&.".concat(g.error)]:{backgroundColor:d.hM},["&.".concat(g.info)]:{backgroundColor:d.s7,"& > *":{color:"".concat(d.E5)}},["&.".concat(g.warning)]:{backgroundColor:d.Wd},...Z}),[Z]);return b?(0,r.jsxs)(l.Z,{...v,className:y(p),sx:w,children:[P(p),k(p,x),C&&(0,r.jsx)(a.Z,{onClick:null!=s?s:function(){for(var e=arguments.length,n=Array(e),o=0;o<e;o++)n[o]=arguments[o];j(!1),null==c||c.call(null,...n)},children:(0,r.jsx)(u.Z,{sx:{fontSize:"1.25rem"}})})]}):(0,r.jsx)(r.Fragment,{})};x.defaultProps=h,n.Z=x},43463:function(e,n,o){o.d(n,{Z:function(){return p}});var r=o(85893),t=o(9122),l=o(47698),a=o(7727),i=o(58219),s=o(36307),c=o(67294),u=o(39971),d=o(46315);let m=e=>{let{disableAutofill:n=!1,endAdornment:o,label:m,onPasswordVisibilityAppend:p,sx:g,inputProps:{type:f,...h}={},type:x=f,...v}=e,[Z,b]=(0,c.useState)(x),j=(0,c.useMemo)(()=>{let e=x===d.Z.password,n=Z===d.Z.password;return(0,r.jsx)(r.Fragment,{children:e&&(0,r.jsx)(a.Z,{onClick:function(){for(var e=arguments.length,o=Array(e),r=0;r<e;r++)o[r]=arguments[r];let t=n?d.Z.text:d.Z.password;b(t),null==p||p.call(null,t,...o)},children:n?(0,r.jsx)(t.Z,{}):(0,r.jsx)(l.Z,{})})})},[x,p,Z]),C=(0,c.useMemo)(()=>({color:u.s7,["& .".concat(i.Z.notchedOutline)]:{borderColor:u.UZ},["& .".concat(i.Z.input)]:{color:u.lD},"&:hover":{["& .".concat(i.Z.notchedOutline)]:{borderColor:u.s7}},["&.".concat(i.Z.focused)]:{color:u.lD,["& .".concat(i.Z.notchedOutline)]:{borderColor:u.s7,"& legend":{paddingRight:m?"1.2em":0}}},...g}),[m,g]),y=(0,c.useMemo)(()=>{let e;if("object"==typeof o){let{props:{children:n=[],...t}}=o;e=(0,c.cloneElement)(o,{...t,children:(0,r.jsxs)(r.Fragment,{children:[j,n]})})}return e},[j,o]),P=(0,c.useMemo)(()=>n?{onFocus:function(){for(var e,n=arguments.length,o=Array(n),r=0;r<n;r++)o[r]=arguments[r];let[t]=o;t.target.readOnly=!1,null==v||null===(e=v.onFocus)||void 0===e||e.call(null,...o)},readOnly:!0}:void 0,[n,null==v?void 0:v.onFocus]);return(0,r.jsx)(s.Z,{endAdornment:y,label:m,inputProps:{type:Z,...h},...v,...P,sx:C})};m.defaultProps={disableAutofill:!1,onPasswordVisibilityAppend:void 0};var p=m},93890:function(e,n,o){o.d(n,{Z:function(){return u}});var r=o(85893),t=o(86972),l=o(35562),a=o(27961),i=o(58202),s=o(90642),c=o(39971),u=e=>{let{children:n,isNotifyRequired:o,sx:u,variant:d="outlined",...m}=e,p={color:"".concat(c.s7,"9F"),["& .".concat(l.Z.root)]:{color:c.s7},["&.".concat(a.Z.focused)]:{backgroundColor:c.s7,borderRadius:c.n_,color:c.E5,padding:".1em .6em"},["&.".concat(a.Z.shrink," .").concat(l.Z.root)]:{display:"none"},...u};return(0,r.jsx)(i.Z,{variant:d,...m,sx:p,children:(0,r.jsxs)(s.Z,{sx:{alignItems:"center",display:"flex",flexDirection:"row"},children:[o&&(0,r.jsx)(t.Z,{sx:{marginLeft:"-.2rem",marginRight:".4rem"}}),n]})})}},23852:function(e,n,o){var r=o(85893),t=o(55386),l=o(89621),a=o(61292),i=o(55730),s=o(7727),c=o(67294),u=o(39971),d=o(17512),m=o(43463),p=o(93890);let g={baseInputProps:void 0,formControlProps:{},helpMessageBoxProps:{},id:"",inputProps:{},inputLabelProps:{},messageBoxProps:{},onHelp:void 0,onHelpAppend:void 0,required:!1,type:void 0,value:""},f=e=>{let{baseInputProps:n,disableAutofill:o,formControlProps:f=g.formControlProps,helpMessageBoxProps:h=g.helpMessageBoxProps,id:x=g.id,inputProps:{endAdornment:v,...Z}=g.inputProps,inputLabelProps:b=g.inputLabelProps,label:j,messageBoxProps:C=g.messageBoxProps,name:y,onBlur:P,onChange:k,onFocus:w,onHelp:M,onHelpAppend:I,required:S=g.required,type:R,value:A=g.value}=e,{text:T=""}=h,[E,O]=(0,c.useState)(!1),q=(0,c.useMemo)(()=>E&&(0,r.jsx)(d.Z,{onClose:()=>{O(!1)},...h}),[h,E]),W=(0,c.useMemo)(()=>void 0!==M||T.length>0,[T,M]),N=(0,c.useCallback)(()=>{let e;return M?e=M:T.length>0&&(e=function(){for(var e=arguments.length,n=Array(e),o=0;o<e;o++)n[o]=arguments[o];O(e=>!e),null==I||I.call(null,...n)}),e},[T,M,I]),_=(0,c.useMemo)(N,[N]);return(0,r.jsxs)(l.Z,{fullWidth:!0,...f,children:[(0,r.jsx)(p.Z,{htmlFor:x,isNotifyRequired:S,...b,children:j}),(0,r.jsx)(m.Z,{disableAutofill:o,endAdornment:(0,r.jsxs)(a.Z,{position:"end",sx:{display:"flex",flexDirection:"row",["& > .".concat(i.Z.root)]:{color:u.s7,padding:".2em"},["& > :not(:first-child, .".concat(i.Z.root,")")]:{marginLeft:".3em"}},children:[v,W&&(0,r.jsx)(s.Z,{onClick:_,tabIndex:-1,children:(0,r.jsx)(t.Z,{})})]}),fullWidth:f.fullWidth,id:x,inputProps:n,label:j,name:y,onBlur:P,onChange:k,onFocus:w,type:R,value:A,...Z}),q,(0,r.jsx)(d.Z,{...C})]})};f.defaultProps=g,n.Z=f},65375:function(e,n,o){o.d(n,{TZ:function(){return x},Lg:function(){return d},bc:function(){return m},CH:function(){return p},s_:function(){return P},V9:function(){return k}});var r=o(85893),t=o(73837),l=o(85413),a=o(7727),i=o(90642),s=o(67294),c=o(39971),u=o(5387),d=e=>{let{headerMarginOffset:n=".3em",ml:o,mv:t="1.4em",sx:l,mb:a=t,mt:u=t,...d}=e,m=(0,s.useMemo)(()=>o?"calc(".concat(o," + ").concat(n,")"):n,[n,o]),p=(0,s.useMemo)(()=>{let e="number"==typeof u?"".concat(u,"px"):u;return"calc(".concat(e," + ").concat(n,")")},[n,u]),g=(0,s.useMemo)(()=>({borderWidth:"1px",borderRadius:c.n_,borderStyle:"solid",borderColor:c.d,paddingBottom:0,position:"relative",...l}),[l]);return(0,r.jsx)(i.Z,{mb:a,ml:m,mt:p,...d,sx:g})},m=e=>{let{sx:n,...o}=e,t=(0,s.useMemo)(()=>({position:"relative",zIndex:20,...n}),[n]);return(0,r.jsx)(i.Z,{padding:".3em .7em",...o,sx:t})},p=e=>{let{children:n}=e;return(0,r.jsxs)(i.Z,{sx:{position:"relative",whiteSpace:"pre-wrap"},children:[(0,r.jsx)(i.Z,{sx:{alignItems:"center",borderColor:c.d,borderRadius:c.n_,borderStyle:"solid",borderWidth:"1px",display:"flex",left:"-.3em",paddingBottom:".2em",paddingLeft:"1em",paddingRight:".7em",paddingTop:".4em",position:"absolute",top:"-.3em",width:"100%",zIndex:"10","& > :first-child":{flexGrow:1},"& > :not(:first-child, :last-child)":{marginRight:".3em"}},children:n}),(0,r.jsx)(i.Z,{sx:{display:"flex",paddingBottom:".4em",paddingRight:"1.7em",visibility:"hidden"},children:n})]})},g=o(90209),f=o(57882);let h="1.2em";var x=e=>{let{children:n,expandInitially:o=!1,header:x,loading:v=!1,panelProps:Z,showHeaderSpinner:b=!1}=e,[j,C]=(0,s.useState)(o),y=(0,s.useMemo)(()=>j?(0,r.jsx)(t.Z,{}):(0,r.jsx)(l.Z,{}),[j]),P=(0,s.useMemo)(()=>j?"auto":".2em",[j]),k=(0,s.useMemo)(()=>"string"==typeof x?(0,r.jsx)(f.Ac,{children:x}):x,[x]),w=(0,s.useMemo)(()=>b&&!j&&v?(0,r.jsx)(g.Z,{progressProps:{style:{height:h,width:h}}}):void 0,[j,v,b]),M=(0,s.useMemo)(()=>j&&v?(0,r.jsx)(g.Z,{sx:{margin:"1em 0"}}):(0,r.jsx)(m,{children:n}),[n,j,v]);return(0,r.jsxs)(d,{...Z,children:[(0,r.jsxs)(p,{children:[(0,r.jsxs)(u.Z,{row:!0,children:[k,w]}),(0,r.jsx)(a.Z,{onClick:()=>{C(e=>!e)},sx:{color:c.s7,padding:".2em"},children:y})]}),(0,r.jsx)(i.Z,{sx:{height:P,overflowY:"hidden"},children:M})]})},v=o(77527),Z=o(8128);let b="Panel",j={paper:"".concat(b,"-paper"),square:"".concat(b,"-square"),topSquare:"".concat(b,"-topSquare"),bottomSquare:"".concat(b,"-bottomSquare")},C=(0,v.ZP)(i.Z)(()=>({margin:"1em",position:"relative",["& .".concat(j.paper)]:{backgroundColor:"".concat(c.v9,"CC"),height:"100%",padding:"2.1em",position:"relative",width:"100%",zIndex:10},["& .".concat(j.square)]:{content:'""',position:"absolute",width:"2.1em",height:"2.1em",border:"1px",borderColor:c.lD,borderWidth:"1px",borderRadius:c.n_,borderStyle:"solid",padding:0,margin:0},["& .".concat(j.topSquare)]:{top:"-.3em",left:"-.3em"},["& .".concat(j.bottomSquare)]:{bottom:"-.3em",right:"-.3em"}})),y=(0,r.jsx)(Z.Z,{styles:{"*::-webkit-scrollbar":{width:".6em"},"*::-webkit-scrollbar-track":{backgroundColor:c.v9},"*::-webkit-scrollbar-thumb":{backgroundColor:c.lD,outline:"1px solid transparent",borderRadius:c.n_}}});var P=e=>{let{children:n,className:o,paperProps:{className:t,...l}={},sx:a,...s}=e;return(0,r.jsxs)(C,{className:o,sx:a,...s,children:[y,(0,r.jsx)(i.Z,{className:"".concat(j.square," ").concat(j.topSquare)}),(0,r.jsx)(i.Z,{className:"".concat(j.square," ").concat(j.bottomSquare)}),(0,r.jsx)(i.Z,{...l,className:"".concat(j.paper," ").concat(t),children:n})]})},k=(0,v.ZP)(i.Z)({alignItems:"center",display:"flex",flexDirection:"row",marginBottom:"1em",width:"100%","& > :first-child":{flexGrow:1},"& > :not(:first-child, :last-child)":{marginRight:".3em"}})},91469:function(e,n,o){var r=o(85893),t=o(90642),l=o(39971);n.Z=e=>{let{children:n,...o}=e;return(0,r.jsx)(t.Z,{color:l.lD,component:"pre",whiteSpace:"pre-wrap",width:"100%",...o,children:n})}},28192:function(e,n,o){var r=o(77527),t=o(90642);let l=(0,r.ZP)(t.Z)({overflowY:"scroll",paddingRight:".4em"});n.Z=l},90209:function(e,n,o){var r=o(85893),t=o(77527),l=o(90642),a=o(65902);let i={progressProps:{}},s=(0,t.ZP)(l.Z)({alignItems:"center",display:"flex",justifyContent:"center"}),c=e=>{let{mt:n="3em",progressProps:o=i.progressProps,...t}=e;return(0,r.jsx)(s,{mt:n,...t,children:(0,r.jsx)(a.Z,{variant:"indeterminate",...o})})};c.defaultProps=i,n.Z=c},57882:function(e,n,o){o.d(n,{Ac:function(){return m},z:function(){return h},Q0:function(){return v},$_:function(){return Z},PJ:function(){return y},KI:function(){return x}});var r=o(85893),t=o(67294),l=o(96788),a=o(39971);let i="BodyText",s={edge:null,inheritColour:!1,inline:!1,inverted:!1,monospaced:!1,selected:!0,text:null},c={inheritColour:"".concat(i,"-inherit-colour"),inverted:"".concat(i,"-inverted"),monospaced:"".concat(i,"-monospaced"),selected:"".concat(i,"-selected"),unselected:"".concat(i,"-unselected")},u=e=>{let{isInheritColour:n,isInvert:o,isMonospace:r,isSelect:t}=e,l=[];return n?l.push(c.inheritColour):o?l.push(c.inverted):t?l.push(c.selected):l.push(c.unselected),r&&l.push(c.monospaced),l.join(" ")},d=e=>{let{children:n,className:o,inheritColour:i=s.inheritColour,inline:d=s.inline,inverted:m=s.inverted,monospaced:p=s.monospaced,selected:g=s.selected,sx:f,text:h=s.text,...x}=e,v=(0,t.useMemo)(()=>d?"inline":void 0,[d]),Z=(0,t.useMemo)(()=>u({isInheritColour:i,isInvert:m,isMonospace:p,isSelect:g}),[i,m,p,g]),b=(0,t.useMemo)(()=>null!=h?h:n,[n,h]);return(0,r.jsx)(l.Z,{className:"".concat(Z," ").concat(o),variant:"subtitle1",...x,sx:{display:v,["&.".concat(c.inverted)]:{color:a.E5},["&.".concat(c.monospaced)]:{fontFamily:"Source Code Pro",fontWeight:400},["&.".concat(c.selected)]:{color:a.lD},["&.".concat(c.unselected)]:{color:a.UZ},...f},children:b})};d.defaultProps=s;var m=d,p=o(77527);let g=(0,p.ZP)(l.Z)({color:a.lD}),f=e=>{let{children:n,text:o,...l}=e,a=(0,t.useMemo)(()=>null!=n?n:o,[n,o]);return(0,r.jsx)(g,{variant:"h4",...l,children:a})};f.defaultProps={text:void 0};var h=f,x=e=>{let{...n}=e;return(0,r.jsx)(m,{variant:"body2",...n})},v=e=>{let{edge:n,sx:o,...l}=e,a=(0,t.useMemo)(()=>"start"===n?0:void 0,[n]),i=(0,t.useMemo)(()=>"end"===n?0:void 0,[n]),s=(0,t.useMemo)(()=>({display:"inline",padding:".1rem .3rem",paddingLeft:a,paddingRight:i,...o}),[a,i,o]);return(0,r.jsx)(x,{monospaced:!0,sx:s,...l})},Z=e=>{let{sx:n,...o}=e;return(0,r.jsx)(x,{monospaced:!0,sx:{alignItems:"center",display:"flex",height:"100%",...n},...o})},b=o(90642);let j={body:e=>(0,r.jsx)(m,{...e}),mono:e=>(0,r.jsx)(Z,{...e}),none:void 0,small:e=>(0,r.jsx)(x,{...e})},C=(0,p.ZP)(b.Z)({backgroundColor:a.Xb,borderRadius:a.n_,color:a.Xb,cursor:"pointer",display:"inline-flex",padding:"0 .6em",width:"fit-content",":focus":{color:"unset",cursor:"text"}});var y=e=>{let{children:n,revealInitially:o=!1,wrapper:l="none",wrapperProps:a}=e,[i,s]=(0,t.useState)(o),c=(0,t.useMemo)(()=>{let e=j[l];return e?e({...a,children:n}):n},[n,l,a]);return(0,r.jsx)(C,{component:"span",onBlur:()=>s(!1),onFocus:()=>s(!0),tabIndex:0,children:i?c:"*****"})}},28937:function(e,n,o){var r=o(87066),t=o(53165);let l=r.Z.create({baseURL:t.Z,transformRequest:r.Z.defaults.transformRequest,transformResponse:r.Z.defaults.transformResponse,validateStatus:e=>e<400,withCredentials:!0});n.Z=l},53165:function(e,n){n.Z="/api"},46315:function(e,n){n.Z={checkbox:"checkbox",number:"number",password:"password",text:"text"}},35338:function(e,n,o){o.d(n,{JW:function(){return d},OU:function(){return p},Qt:function(){return g},ah:function(){return u},bQ:function(){return m},tf:function(){return c}});let r="[a-z0-9]",t="[a-z0-9-]",l="[0-9a-f]",a="(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9]|)[0-9])",i="(?:".concat(a,"[.]){3}").concat(a),s="".concat(l,"{8}-(?:").concat(l,"{4}-){3}").concat(l,"{12}");new RegExp("^(?:".concat(r,"(?:").concat(t,"{0,61}").concat(r,")?[.])+").concat(r).concat(t,"{0,61}").concat(r,"$"));let c=new RegExp("^".concat(i,"$")),u=new RegExp("^(?:".concat(i,"\\s*,\\s*)*").concat(i,"$")),d=/(?=.*passw)(?!.*script).*/i,m=new RegExp("^".concat(l,"{2}(?::").concat(l,"{2}){5}$")),p=/^[^'"/\\><}{]*$/,g=RegExp("^".concat(s,"$"),"i")},81951:function(e,n){n.Z=function(){for(var e=arguments.length,n=Array(e),o=0;o<e;o++)n[o]=arguments[o];return fetch(...n).then(e=>e.json())}},11100:function(e,n){let o=e=>{let n={code:"",message:"",name:""};return e&&"object"==typeof e?("code"in e&&(n.code=String(e.code)),"message"in e&&(n.message=String(e.message)),"name"in e&&(n.name=String(e.name)),n):null};n.Z=function(e){let{onRequestError:n=e=>({children:"Incomplete request; reason: ".concat(e,"."),type:"error"}),onResponseErrorAppend:r,onSetupError:t=e=>({children:"Failed to setup request; reason: ".concat(e,"."),type:"error"}),onResponseError:l=e=>{var n;let{data:t,status:l,statusText:a}=e,i={},s=o(t);return(s&&(i={children:"".concat(s.name,"(").concat(s.code,"): ").concat(s.message)}),l>=500)?(i.type="error",i.children||(i.children="API responded with ".concat(l," (").concat(a,")! Please check its systemd service logs.")),i):(i.type="warning",i.children||(i.children="API responded with ".concat(l," (").concat(a,").")),null!==(n=null==r?void 0:r.call(null,e))&&void 0!==n?n:i)}}=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},{request:a,response:i,message:s}=e;return i?l(i):a?n(a):t(s)}},98717:function(e,n){n.Z=function(e){let{fillString:n="0",maxLength:o=2,which:r="Start"}=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{};return String(e)["pad".concat(r)](o,n)}},71487:function(e,n,o){var r=o(67294);n.Z=(e,n)=>"string"==typeof e?(0,r.createElement)(n,null,e):e}}]);