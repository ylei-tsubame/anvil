"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[436],{47856:function(e,n,t){var i=t(85893),o=t(77527),l=t(73939),r=t(61481),s=t(67294),c=t(39971);let a="Checkbox",d={invert:"".concat(a,"-invert"),thinPadding:"".concat(a,"-thin-padding")},u=(0,o.ZP)(l.Z)({color:c.s7,["&.".concat(r.Z.checked)]:{color:c.s7},["&.".concat(d.invert)]:{color:c.E5,["&.".concat(r.Z.checked)]:{color:c.E5}},["&.".concat(d.thinPadding)]:{padding:".2em"}});n.Z=e=>{let{className:n,invert:t,thinPadding:o,...l}=e,r=(0,s.useMemo)(()=>{let e=[];return n&&e.push(n),t&&e.push(d.invert),o&&e.push(d.thinPadding),e.join(" ")},[n,t,o]);return(0,i.jsx)(u,{className:r,...l})}},82092:function(e,n,t){var i=t(77527),o=t(56912),l=t(39971);let r=(0,i.ZP)(o.Z)({backgroundColor:l.d});n.Z=r},25436:function(e,n,t){t.d(n,{Z:function(){return es}});var i=t(85893),o=t(36117),l=t(77527),r=t(36795),s=t(90642),c=t(19929),a=t(7727),d=t(67294),u=t(39971),h=t(60018),m=t(9527),x=t(37958),p=t(47407),g=t(19304),j=t(52311),Z=t(55756);let v=[{text:"Anvil",image:"/pngs/anvil_icon_on.png",uri:"/manage-element"},{text:"Files",image:"/pngs/files_on.png",uri:"/file-manager"},{text:"Configure",image:"/pngs/configure_icon_on.png",uri:"/config"},{text:"Mail",image:"/pngs/email_on.png",uri:"/mail-config"},{text:"Help",image:"/pngs/help_icon_on.png",uri:"https://alteeve.com/w/Support"}],f={width:"40em",height:"40em"};var w=t(28937),P=t(82092),b=t(5387),k=t(11100),A=t(57882);let C="AnvilDrawer",I={actionIcon:"".concat(C,"-actionIcon"),list:"".concat(C,"-list")},M=(0,l.ZP)(x.ZP)(()=>({["& .".concat(I.list)]:{width:"200px"},["& .".concat(I.actionIcon)]:{fontSize:"2.3em",color:u.of}}));var y=e=>{let{open:n,setOpen:t}=e,[o]=(0,Z.fP)(["suiapi.session"]),l=o["suiapi.session"];return(0,i.jsx)(M,{anchor:"left",open:n,onClose:()=>t(!n),slotProps:{backdrop:{invisible:!0}},children:(0,i.jsx)("div",{role:"presentation",children:(0,i.jsxs)(p.Z,{className:I.list,children:[(0,i.jsx)(g.ZP,{children:(0,i.jsx)(A.Ac,{children:(null==l?void 0:l.user)?(0,i.jsxs)(i.Fragment,{children:["Welcome, ",l.user.name]}):"Unregistered"})}),(0,i.jsx)(P.Z,{}),(0,i.jsx)(j.Z,{component:"a",href:"/index.html",children:(0,i.jsxs)(b.Z,{fullWidth:!0,row:!0,spacing:"2em",children:[(0,i.jsx)(h.Z,{className:I.actionIcon}),(0,i.jsx)(A.Ac,{children:"Dashboard"})]})}),v.map(e=>(0,i.jsx)(j.Z,{component:"a",href:e.uri,children:(0,i.jsxs)(b.Z,{fullWidth:!0,row:!0,spacing:"2em",children:[(0,i.jsx)("img",{alt:e.text,src:e.image,...f}),(0,i.jsx)(A.Ac,{children:e.text})]})},"anvil-drawer-".concat(e.image))),(0,i.jsx)(j.Z,{onClick:()=>{w.Z.put("/auth/logout").then(()=>{window.location.replace("/login")}).catch(e=>{(0,k.Z)(e)})},children:(0,i.jsxs)(b.Z,{fullWidth:!0,row:!0,spacing:"2em",children:[(0,i.jsx)(m.Z,{className:I.actionIcon}),(0,i.jsx)(A.Ac,{children:"Logout"})]})})]})})})};let S="1.7em",E={iconProps:{},indicatorProps:{},indicatorTextProps:{},initialIndicatorValue:!1},W={small:"24%",medium:"50%"},F={small:".1rem",medium:"0rem"},N=(0,d.forwardRef)((e,n)=>{let{icon:t,iconProps:{sx:o,...l}=E.iconProps,indicatorProps:{sx:r,...c}=E.indicatorProps,indicatorTextProps:{sx:a,...h}=E.indicatorTextProps,initialIndicatorValue:m=E.initialIndicatorValue,sx:x}=e,[p,g]=(0,d.useState)(m),j=(0,d.useCallback)((e,n,t)=>(0,i.jsx)(b.Z,{row:!0,...c,sx:{backgroundColor:u.Ej,borderColor:u.E5,borderRadius:"50%",borderStyle:"solid",borderWidth:".1em",bottom:t,boxSizing:"content-box",height:0,justifyContent:"center",paddingBottom:n,position:"absolute",right:t,width:n,...r},children:e}),[r,c]),Z=(0,d.useCallback)(e=>(0,i.jsx)(A.Ac,{...h,sx:{fontWeight:"500",paddingTop:"100%",...a},children:Number(e)>9?"".concat(9,"+"):e}),[a,h]),v=(0,d.useMemo)(()=>{let e;if(p){let n;let t=W.small,i=F.small;Number.isFinite(p)&&(n=Z(p),t=W.medium,i=F.medium),e=j(n,t,i)}return e},[j,Z,p]);return(0,d.useImperativeHandle)(n,()=>({indicate:e=>g(e)}),[g]),(0,i.jsxs)(s.Z,{sx:{height:S,width:S,position:"relative",...x},children:[(0,d.createElement)(t,{...l,sx:{height:"100%",width:"100%",...o}}),v]})});N.defaultProps=E,N.displayName="IconWithIndicator";var z=t(33466),B=t(53165),O=t(45036),_=t(18745),R=t(89540),L=t(8506),H=t(35338),T=t(41373),D=t(45328),J=t(29873),K=t(98717),G=t(65375),U=t(14631),V=t(91469),Q=t(90209),X=t(29255);let Y=e=>{let n=new Date(1e3*e),t=n.getMonth()+1,i=n.getDate(),o=n.getHours(),l=n.getMinutes(),r=n.getSeconds();return"".concat((0,K.Z)(t),"-").concat((0,K.Z)(i),", ").concat((0,K.Z)(o),":").concat((0,K.Z)(l),":").concat((0,K.Z)(r))};var $=e=>{let{refreshInterval:n=1e4,uuid:t}=e,o=(0,_.Z)(),l=(0,R.Z)(o.breakpoints.up("sm")),[r,s]=(0,d.useState)({children:"Job ".concat(t," details unavailable"),type:"warning"}),{data:c,isLoading:a}=(0,U.Z)("".concat(B.Z,"/job/").concat(t),{onError:e=>{s({children:"Failed to get job ".concat(t," details. Error: ").concat(e),type:"error"})},refreshInterval:n}),u=(0,X.zO)(),h=(0,d.useMemo)(()=>c&&Object.entries(c.data).map(e=>{let[n,t]=e,o=H.JW.test(t.name)&&t.value.length>0?(0,i.jsx)(A.PJ,{children:t.value}):t.value;return(0,i.jsxs)(A.KI,{monospaced:!0,noWrap:!0,textOverflow:"initial",children:[t.name,"=",o]},"data-".concat(n))}),[c]),m=(0,d.useMemo)(()=>{if(!c)return;let e=Object.values(c.status).reduce((e,n)=>"".concat(e).concat(n.value,"\n\n"),"").trimEnd();return(0,i.jsx)(V.Z,{children:e})},[c]),x=(0,d.useMemo)(()=>c&&Y(c.started),[c]),p=(0,d.useMemo)(()=>c&&Y(c.modified),[c]),g=(0,d.useMemo)(()=>c&&(0,X.F6)(u-c.started),[c,u]),j=(0,d.useMemo)(()=>c&&(0,X.F6)(u-c.modified),[c,u]),Z=(0,d.useMemo)(()=>c?c.started?(0,i.jsxs)(i.Fragment,{children:["~",g," ago",l&&" (".concat(x,")")]}):(0,i.jsx)(i.Fragment,{children:"Not started"}):void 0,[l,c,g,x]),v=c?(0,i.jsx)(O.VZ,{children:(0,i.jsxs)(L.ZP,{columns:1,container:!0,rowGap:".6em",children:[(0,i.jsx)(L.ZP,{item:!0,width:"100%",children:(0,i.jsx)(A.Ac,{children:c.title})}),(0,i.jsx)(L.ZP,{item:!0,width:"100%",children:(0,i.jsx)(T.ko,{progressPercentage:c.progress})}),(0,i.jsx)(L.ZP,{item:!0,width:"100%",children:(0,i.jsx)(A.Ac,{children:c.description})}),(0,i.jsxs)(L.ZP,{columns:2,container:!0,item:!0,children:[(0,i.jsx)(L.ZP,{item:!0,xs:1,children:(0,i.jsx)(A.Ac,{children:"Host"})}),(0,i.jsx)(L.ZP,{item:!0,xs:1,children:(0,i.jsx)(A.KI,{monospaced:!0,noWrap:!0,textAlign:"end",children:l?c.host.name:c.host.shortName})}),(0,i.jsx)(L.ZP,{item:!0,xs:1,children:(0,i.jsx)(A.Ac,{children:"PID"})}),(0,i.jsx)(L.ZP,{item:!0,xs:1,children:(0,i.jsx)(A.KI,{monospaced:!0,noWrap:!0,textAlign:"end",children:c.pid})}),(0,i.jsx)(L.ZP,{item:!0,xs:1,children:(0,i.jsx)(A.Ac,{children:"Started"})}),(0,i.jsx)(L.ZP,{item:!0,xs:1,children:(0,i.jsx)(A.Ac,{noWrap:!0,textAlign:"end",children:Z})}),(0,i.jsx)(L.ZP,{item:!0,xs:1,children:(0,i.jsx)(A.Ac,{children:"Last updated"})}),(0,i.jsx)(L.ZP,{item:!0,xs:1,children:(0,i.jsxs)(A.Ac,{noWrap:!0,textAlign:"end",children:["~",j," ago",l&&" (".concat(p,")")]})})]}),(0,i.jsx)(L.ZP,{item:!0,width:"100%",children:(0,i.jsx)(G.TZ,{header:(0,i.jsxs)(b.Z,{fullWidth:!0,growFirst:!0,row:!0,children:[(0,i.jsx)(A.Ac,{children:"Command"}),(0,i.jsx)(D.Z,{iconProps:{fontSize:"small"},mapPreset:"copy",onClick:()=>navigator.clipboard.writeText(c.command),size:"small"})]}),panelProps:{mb:0,mt:0},children:(0,i.jsx)(b.Z,{overflow:"scroll",paddingBottom:".8em",children:(0,i.jsx)(A.KI,{monospaced:!0,noWrap:!0,textOverflow:"initial",width:"max-content",children:c.command})})})}),(0,i.jsx)(L.ZP,{item:!0,width:"100%",children:(0,i.jsx)(G.TZ,{header:(0,i.jsxs)(b.Z,{fullWidth:!0,growFirst:!0,row:!0,children:[(0,i.jsx)(A.Ac,{children:"Data"}),(0,i.jsx)(D.Z,{iconProps:{fontSize:"small"},mapPreset:"copy",onClick:()=>{let e=Object.values(c.data).reduce((e,n)=>{let{name:t,value:i}=n;return"".concat(e).concat(t,"=").concat(i,"\n")},"");navigator.clipboard.writeText(e)},size:"small"})]}),panelProps:{mb:0,mt:0},children:(0,i.jsx)(b.Z,{overflow:"scroll",paddingBottom:".8em",spacing:".2em",sx:{"& > *":{width:"max-content"}},children:h})})}),(0,i.jsx)(L.ZP,{item:!0,width:"100%",children:(0,i.jsxs)(G.Lg,{mb:0,mt:0,children:[(0,i.jsx)(G.CH,{children:(0,i.jsx)(A.Ac,{children:"Status"})}),(0,i.jsx)(G.bc,{children:m})]})})]})}):(0,i.jsx)(J.Z,{...r});return a?(0,i.jsx)(Q.Z,{}):v},q=t(18541),ee=t(21758);let en="20em",et={getJobUrl:()=>"".concat(B.Z,"/job"),onFetchSuccessAppend:void 0,openInitially:!1,refreshInterval:1e4},ei=(0,d.forwardRef)((e,n)=>{let{getJobUrl:t=et.getJobUrl,onFetchSuccessAppend:o,openInitially:l=et.openInitially,refreshInterval:r=et.refreshInterval}=e,s=(0,d.useRef)(null),[c,a]=(0,d.useState)(),[u,h]=(0,d.useState)(l),[m,x]=(0,d.useState)(),p=(0,d.useMemo)(()=>(0,X.zO)(),[]),g=(0,X.zO)(),{data:j}=(0,U.Z)(t(p),{onError:()=>{},onSuccess:e=>{null==o||o.call(null,e)},refreshInterval:r});(0,d.useImperativeHandle)(n,()=>({setAnchor:e=>x(e),setOpen:e=>h(e)}),[]);let Z=(0,d.useMemo)(()=>(0,i.jsx)(b.Z,{children:(0,i.jsx)(q.Z,{allowItemButton:!0,listEmpty:"No running or recently completed jobs.",listItems:j,listProps:{sx:{maxHeight:en,width:en}},onItemClick:e=>{var n;let{uuid:t}=e;a(t),null===(n=s.current)||void 0===n||n.setOpen(!0)},renderListItem:(e,n)=>{let t;let{host:o,name:l,progress:r,started:s,title:c}=n,{shortName:a}=o;if(s){let{unit:e,value:n}=(0,X._J)(g-s);t="Started ~".concat(n).concat(e," ago on ").concat(a,".")}else t="Queued on ".concat(a);return(0,i.jsxs)(b.Z,{fullWidth:!0,spacing:".2em",children:[(0,i.jsxs)(b.Z,{row:!0,spacing:".5em",children:[(0,i.jsx)(ee.Z,{slotProps:{pie:{sx:{flexShrink:0}}},value:r}),(0,i.jsx)(A.Ac,{sx:{overflowX:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"},children:c||l})]}),(0,i.jsx)(A.Ac,{children:t})]})},scroll:!0})}),[j,g]);return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(z.Z,{anchorEl:m,onClose:()=>{h(!1),x(void 0)},open:u,variant:"menu",children:Z}),(0,i.jsx)(O.Js,{header:"",ref:s,showClose:!0,wide:!0,children:c&&(0,i.jsx)($,{uuid:c})})]})});ei.defaultProps=et,ei.displayName="JobSummary";let eo="Header",el={input:"".concat(eo,"-input"),barElement:"".concat(eo,"-barElement"),iconBox:"".concat(eo,"-iconBox"),searchBar:"".concat(eo,"-searchBar"),icons:"".concat(eo,"-icons")},er=(0,l.ZP)(r.Z)(e=>{let{theme:n}=e;return{paddingTop:n.spacing(.5),paddingBottom:n.spacing(.5),paddingLeft:n.spacing(3),paddingRight:n.spacing(3),borderBottom:"solid 1px",borderBottomColor:u.hM,position:"static",["& .".concat(el.input)]:{height:"2.8em",width:"30vw",backgroundColor:n.palette.secondary.main,borderRadius:u.n_},["& .".concat(el.barElement)]:{padding:0},["& .".concat(el.iconBox)]:{[n.breakpoints.down("sm")]:{display:"none"}},["& .".concat(el.searchBar)]:{[n.breakpoints.down("sm")]:{flexGrow:1,paddingLeft:"15vw"}},["& .".concat(el.icons)]:{paddingLeft:".1em",paddingRight:".1em"}}});var es=()=>{let e=(0,d.useRef)({}),n=(0,d.useRef)({}),[t,l]=(0,d.useState)(!1);return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(er,{children:(0,i.jsxs)(s.Z,{display:"flex",justifyContent:"space-between",flexDirection:"row",children:[(0,i.jsx)(b.Z,{row:!0,children:(0,i.jsx)(c.Z,{onClick:()=>l(!t),children:(0,i.jsx)("img",{alt:"",src:"/pngs/logo.png",width:"160",height:"40"})})}),(0,i.jsx)(b.Z,{className:el.iconBox,row:!0,spacing:0,children:(0,i.jsx)(s.Z,{children:(0,i.jsx)(a.Z,{onClick:e=>{var t,i;let{currentTarget:o}=e;null===(t=n.current.setAnchor)||void 0===t||t.call(null,o),null===(i=n.current.setOpen)||void 0===i||i.call(null,!0)},sx:{color:u.of,padding:"0 .1rem"},children:(0,i.jsx)(N,{icon:o.Z,ref:e})})})})]})}),(0,i.jsx)(y,{open:t,setOpen:l}),(0,i.jsx)(ei,{onFetchSuccessAppend:n=>{var t;null===(t=e.current.indicate)||void 0===t||t.call(null,Object.keys(n).length>0)},ref:n})]})}},18541:function(e,n,t){var i=t(85893),o=t(67294),l=t(53839),r=t(89090),s=t(43562),c=t(17071),a=t(90642),d=t(7638),u=t(19304),h=t(52311),m=t(47407),x=t(39971),p=t(47856),g=t(82092),j=t(5387),Z=t(45328),v=t(90209),f=t(57882);let w=(0,o.forwardRef)(e=>{let{allowCheckAll:n=!1,allowEdit:t=!1,allowItemButton:w=!1,disableDelete:P=!1,edit:b=!1,flexBoxProps:k,getListCheckboxProps:A,getListItemCheckboxProps:C,header:I,headerSpacing:M=".3em",insertHeader:y=!0,listEmpty:S,listItemIconMinWidth:E="56px",listItemKeyPrefix:W="list",listItemProps:{sx:F,...N}={},listItems:z,listProps:{sx:B,...O}={},loading:_,onAdd:R,onDelete:L,onEdit:H,onAllCheckboxChange:T,onItemCheckboxChange:D,onItemClick:J,renderListItem:K=e=>(0,i.jsx)(f.Ac,{children:e}),renderListItemCheckboxState:G,scroll:U=!1,allowAddItem:V=t,allowCheckItem:Q=t,allowDelete:X=t,allowEditItem:Y=t}=e,$=(0,o.useMemo)(()=>"calc(".concat(E," - ").concat(M,")"),[M,E]),q=(0,o.useMemo)(()=>V?(0,i.jsx)(Z.Z,{onClick:R,size:"small",children:(0,i.jsx)(l.Z,{})}):void 0,[V,R]),ee=(0,o.useMemo)(()=>b&&X?(0,i.jsx)(Z.Z,{disabled:P,onClick:L,size:"small",sx:{backgroundColor:x.hM,color:x.s7,"&:hover":{backgroundColor:"".concat(x.hM,"F0")}},children:(0,i.jsx)(r.Z,{})}):void 0,[P,X,b,L]),en=(0,o.useMemo)(()=>{if(Y)return(0,i.jsx)(Z.Z,{onClick:H,size:"small",children:b?(0,i.jsx)(s.Z,{sx:{color:x.Ej}}):(0,i.jsx)(c.Z,{})})},[Y,b,H]),et=(0,o.useMemo)(()=>{let e;return b&&Q&&(e=n?(0,i.jsx)(a.Z,{sx:{minWidth:$},children:(0,i.jsx)(p.Z,{edge:"start",onChange:T,...null==A?void 0:A.call(null)})}):(0,i.jsx)(g.Z,{sx:{minWidth:$}})),e},[$,A,n,Q,b,T]),ei=(0,o.useMemo)(()=>{let e=typeof I;return y&&I?(0,i.jsxs)(j.Z,{row:!0,spacing:M,sx:{height:"2.4em"},children:[et,["boolean","string"].includes(e)?(0,i.jsxs)(i.Fragment,{children:["string"===e&&(0,i.jsx)(f.Ac,{children:I}),(0,i.jsx)(g.Z,{sx:{flexGrow:1}})]}):I,ee,en,q]}):I},[q,et,ee,en,I,M,y]),eo=(0,o.useMemo)(()=>"string"==typeof S?(0,i.jsx)(f.Ac,{align:"center",children:S}):S,[S]),el=(0,o.useCallback)((e,n,t)=>b&&Q?(0,i.jsx)(d.Z,{sx:{minWidth:E},children:(0,i.jsx)(p.Z,{checked:n,edge:"start",onChange:function(){for(var n=arguments.length,t=Array(n),i=0;i<n;i++)t[i]=arguments[i];return null==D?void 0:D.call(null,e,...t)},...t})}):void 0,[Q,b,E,D]),er=(0,o.useMemo)(()=>{if(_)return(0,i.jsx)(v.Z,{});if(!z)return eo;let e=Object.entries(z);return e.length<=0?eo:e.map(e=>{let[n,t]=e,l=K(n,t);return(0,o.createElement)(u.ZP,{...N,key:"".concat(W,"-").concat(n),sx:{paddingLeft:0,paddingRight:0,...F},children:[el(n,null==G?void 0:G.call(null,n,t),null==C?void 0:C.call(null,n,t)),w?(0,i.jsx)(h.Z,{onClick:function(){for(var e=arguments.length,i=Array(e),o=0;o<e;o++)i[o]=arguments[o];null==J||J.call(null,t,n,...i)},sx:{borderRadius:x.n_},children:l}):l]})})},[C,w,eo,el,W,F,z,_,J,K,G,N]),es=(0,o.useMemo)(()=>U?{maxHeight:"100%",overflowY:"scroll"}:void 0,[U]);return(0,i.jsxs)(j.Z,{spacing:0,...k,children:[ei,(0,i.jsx)(m.Z,{...O,sx:{paddingBottom:0,paddingTop:0,...es,...B},children:er})]})});w.displayName="List",n.Z=w},21758:function(e,n,t){var i=t(85893),o=t(77527),l=t(27398),r=t(90642),s=t(67294),c=t(39971);let a="PieProgress",d={complete:"".concat(a,"-complete"),inProgress:"".concat(a,"-in-progress")},u=(0,o.ZP)(l.Z)({["&.".concat(d.complete)]:{color:c.Ej},["&.".concat(d.inProgress)]:{color:c.Wd}}),h=(0,o.ZP)(l.Z)({color:c.rr}),m=(0,o.ZP)(r.Z)({position:"relative"});n.Z=e=>{var n;let{slotProps:t}=e,o=null==t?void 0:t.pie,{value:l=null==o?void 0:o.value}=e,r=null!==(n=null==o?void 0:o.size)&&void 0!==n?n:"1.6em",c=(0,s.useMemo)(()=>l&&100===l?d.complete:d.inProgress,[l]),a=(0,s.useMemo)(()=>{var e,n,i,o,l;let s=null==t?void 0:t.underline,c=null!==(i=null==s?void 0:s.thickness)&&void 0!==i?i:2,a=c*(null!==(o=null==s?void 0:null===(e=s.offset)||void 0===e?void 0:e.multiplier)&&void 0!==o?o:2),d=null!==(l=null==s?void 0:null===(n=s.offset)||void 0===n?void 0:n.unit)&&void 0!==l?l:"px",u=.5*a;return{size:"calc(".concat(r," + ").concat(a).concat(d,")"),sx:{position:"absolute",top:"-".concat(u).concat(d),left:"-".concat(u).concat(d)},thickness:c,value:100,variant:"determinate",...null==t?void 0:t.underline}},[r,null==t?void 0:t.underline]);return(0,i.jsxs)(m,{...null==t?void 0:t.box,children:[(0,i.jsx)(h,{...a}),(0,i.jsx)(u,{classes:{root:c},size:r,thickness:22,value:l,variant:"determinate",...o})]})}},14631:function(e,n,t){var i=t(8100),o=t(81951);n.Z=function(e){let{refreshInterval:n=5e3,onSuccess:t}=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},{data:l,error:r}=(0,i.ZP)(e,o.Z,{refreshInterval:n,onSuccess:t});return{data:l,isLoading:!r&&!l,error:r}}},29255:function(e,n,t){t.d(n,{F6:function(){return r},Z$:function(){return o},_J:function(){return l},zO:function(){return i}});let i=e=>{let n=Date.now();return e||(n=Math.floor(n/1e3)),n},o=function(e,n){let{ms:t}=arguments.length>2&&void 0!==arguments[2]?arguments[2]:{};return i(t)-e<=n},l=e=>{var n;let t=e,[i,o,l]=[...[60,60].reduce((e,n)=>{let i=t%n;return e.push(i),t=(t-i)/n,e},[]),t],r=null!==(n=[{unit:"h",value:l},{unit:"m",value:o}].find(e=>{let{value:n}=e;return n}))&&void 0!==n?n:{unit:"s",value:i};return{h:l,m:o,s:i,...r}},r=function(){for(var e=arguments.length,n=Array(e),t=0;t<e;t++)n[t]=arguments[t];let{value:i,unit:o}=l(...n);return"".concat(i).concat(o)}}}]);