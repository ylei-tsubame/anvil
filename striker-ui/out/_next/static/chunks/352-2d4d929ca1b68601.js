"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[352],{45842:function(e,n,t){t.d(n,{SJ:function(){return P},MB:function(){return J},$x:function(){return L},bC:function(){return K}});var r=t(85893),s=t(83688),l=t(55751),o=t(38444),c=t(60018),i=t(77527),a=t(90642),u=t(96788),d=t(5152),h=t.n(d),x=t(67294),f=t(55756),v=t(45328);let m="0xffe3",p="0xffe9";var g=[{keys:"Ctrl + Alt + Delete",scans:[]},{keys:"Ctrl + Alt + F1",scans:[m,p,"0xffbe"]},{keys:"Ctrl + Alt + F2",scans:[m,p,"0xffbf"]},{keys:"Ctrl + Alt + F3",scans:[m,p,"0xffc0"]},{keys:"Ctrl + Alt + F4",scans:[m,p,"0xffc1"]},{keys:"Ctrl + Alt + F5",scans:[m,p,"0xffc2"]},{keys:"Ctrl + Alt + F6",scans:[m,p,"0xffc3"]},{keys:"Ctrl + Alt + F7",scans:[m,p,"0xffc4"]},{keys:"Ctrl + Alt + F8",scans:[m,p,"0xffc5"]},{keys:"Ctrl + Alt + F9",scans:[m,p,"0xffc6"]}],j=t(37600),C=t(18766),b=t(65375),Z=t(54420),k=t(90209),y=t(57882),w=t(99246);let A="FullSize",B={displayBox:"".concat(A,"-displayBox"),spinnerBox:"".concat(A,"-spinnerBox")},F=(0,i.ZP)("div")(()=>({["& .".concat(B.displayBox)]:{width:"75vw",height:"75vh"},["& .".concat(B.spinnerBox)]:{flexDirection:"column",width:"75vw",height:"75vh",alignItems:"center",justifyContent:"center"}})),M=h()(()=>Promise.all([t.e(460),t.e(791)]).then(t.bind(t,38791)),{loadableGenerated:{webpack:()=>[38791]},ssr:!1}),S={1e3:"in-use by another process?",1006:"destination is down?"},I=(e,n)=>"ws://".concat(e,"/ws/server/vnc/").concat(n);var P=e=>{let{onClickCloseButton:n,serverUuid:t,serverName:i,vncReconnectTimerStart:d=10}=e,[h]=(0,f.fP)(["suiapi.vncerror.".concat(t)]),m=(0,w.Z)(),[p,A]=(0,x.useState)(null),[P,_]=(0,x.useState)(void 0),[z,E]=(0,x.useState)(!1),[D,N]=(0,x.useState)(!1),[T,U]=(0,x.useState)(),[R,q]=(0,x.useState)(),[L,G]=(0,x.useState)(d),O=(0,x.useRef)(null),J=(0,x.useRef)(null),K=e=>{A(e.currentTarget)},$=e=>{if(O.current){if(e.length){for(let n=0;n<=e.length-1;n+=1)O.current.sendKey(e[n],1);for(let n=e.length-1;n>=0;n-=1)O.current.sendKey(e[n],0)}else O.current.sendCtrlAltDel();A(null)}},H=(0,x.useCallback)(()=>{E(!0),N(!1),_({url:I(window.location.host,t)})},[t]),V=(0,x.useCallback)(()=>{(null==O?void 0:O.current)&&(O.current.disconnect(),O.current=null),_(void 0)},[]),W=(0,x.useCallback)(()=>{V(),H()},[H,V]),Q=(0,x.useCallback)(()=>{let e=setInterval(()=>{G(n=>{let t=n-1;return t<1&&clearInterval(e),t})},1e3)},[]),X=(0,x.useCallback)(()=>{E(!1)},[]),Y=(0,x.useCallback)(e=>{let{detail:n}=e,{clean:t}=n;t||(E(!1),N(!0),Q())},[Q]),ee=(0,x.useCallback)(e=>{if(!e){U(void 0);return}let{code:n,reason:r}=e,s="ws: ".concat(n),l=S[n];l&&(s+=" (".concat(l,")")),r&&(s+=", ".concat(r)),U(s);let o=h["suiapi.vncerror.".concat(t)];if(!o){q(void 0);return}let{code:c,message:i}=o;q("api: ".concat(c,", ").concat(i))},[h,t]),en=(0,x.useMemo)(()=>!z&&!D,[z,D]),et=(0,x.useMemo)(()=>(0,r.jsx)(a.Z,{children:(0,r.jsx)(v.Z,{onClick:()=>{var e;null===(e=J.current)||void 0===e||e.requestFullscreen()},children:(0,r.jsx)(s.Z,{})})}),[]),er=(0,x.useMemo)(()=>(0,r.jsxs)(a.Z,{children:[(0,r.jsx)(v.Z,{onClick:K,children:(0,r.jsx)(l.Z,{})}),(0,r.jsx)(j.Z,{muiMenuProps:{anchorEl:p,keepMounted:!0,onClose:()=>A(null)},open:!!p,children:g.map(e=>{let{keys:n,scans:t}=e;return(0,r.jsx)(C.Z,{onClick:()=>$(t),children:(0,r.jsx)(u.Z,{variant:"subtitle1",children:n})},n)})})]}),[p]),es=(0,x.useMemo)(()=>(0,r.jsx)(a.Z,{children:(0,r.jsx)(v.Z,{onClick:function(){for(var e=arguments.length,t=Array(e),r=0;r<e;r++)t[r]=arguments[r];V(),null==n||n.call(null,...t)},children:(0,r.jsx)(o.Z,{})})}),[V,n]),el=(0,x.useMemo)(()=>(0,r.jsx)(a.Z,{children:(0,r.jsx)(v.Z,{onClick:()=>{window&&(V(),window.location.assign("/"))},children:(0,r.jsx)(c.Z,{})})}),[V]),eo=(0,x.useMemo)(()=>en&&(0,r.jsxs)(r.Fragment,{children:[et,er,(0,r.jsx)(Z.Z,{serverName:i,serverState:"running",serverUuid:t}),el,es]}),[et,er,el,i,t,en,es]);return(0,x.useEffect)(()=>{0===L&&(G(d),W())},[W,L,d]),(0,x.useEffect)(()=>{m&&H()},[H,m]),(0,r.jsxs)(b.s_,{children:[(0,r.jsxs)(b.V9,{children:[(0,r.jsx)(y.z,{text:"Server: ".concat(i)}),eo]}),(0,r.jsxs)(F,{children:[(0,r.jsx)(a.Z,{display:en?"flex":"none",className:B.displayBox,children:(0,r.jsx)(M,{onConnect:X,onDisconnect:Y,onWsClose:ee,rfb:O,rfbConnectArgs:P,rfbScreen:J})}),!en&&(0,r.jsxs)(a.Z,{display:"flex",className:B.spinnerBox,textAlign:"center",children:[z&&(0,r.jsxs)(r.Fragment,{children:[(0,r.jsxs)(y.z,{children:["Connecting to ",i,"."]}),(0,r.jsx)(k.Z,{})]}),D&&(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(y.z,{children:"Can't connect to the server."}),(0,r.jsx)(y.Ac,{children:R}),(0,r.jsx)(y.Ac,{children:T}),(0,r.jsxs)(y.z,{mt:".5em",children:["Retrying in ",L,"."]})]})]})]})]})},_=t(10617),z=t(65625),E=t(7727),D=t(48403),N=t.n(D),T=t(82492),U=t.n(T),R=t(39971),q=t(21758),L=(0,i.ZP)(a.Z)({alignItems:"center",display:"flex",justifyContent:"center",margin:".2em",overflow:"hidden",position:"relative"}),G=t(29255),O=t(5499),J=function(){for(var e=arguments.length,n=Array(e),t=0;t<e;t++)n[t]=arguments[t];let[s]=n,{onClick:l,server:o,slotProps:c,slots:i}=s,{href:u="/server?name=".concat(o.name,"&view=vnc")}=s,{data:d,loading:h}=(0,O.Z)("/server/".concat(o.uuid,"?ss=1"),{refreshInterval:6e4}),f=null==d?void 0:d.screenshot,v=null==d?void 0:d.timestamp,m=(0,G.zO)(),p=(0,x.useMemo)(()=>!!v&&!(0,G.Z$)(v,300),[v]),g=(0,x.useMemo)(()=>{var e;return null!==(e=null==i?void 0:i.screenshotBox)&&void 0!==e?e:(0,r.jsx)(L,{})},[null==i?void 0:i.screenshotBox]),j=(0,x.useMemo)(()=>({...null==c?void 0:c.screenshotBox}),[null==c?void 0:c.screenshotBox]),C=(0,x.useMemo)(()=>{let e,n;if(o.jobs)return(0,x.cloneElement)(g,j,(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(y.Ac,{children:"Provisioning..."}),Object.values(o.jobs).map((e,n)=>{let{peer:t,progress:s,uuid:l}=e;return(0,r.jsx)(q.Z,{slotProps:{box:{sx:{position:"absolute"}},pie:{size:"calc(7em - ".concat(1.5*n,"em)"),sx:{opacity:t?.6:void 0,["& .".concat(z.Z.circle)]:{strokeLinecap:"round"}},thickness:3},underline:{thickness:s?0:1}},value:s},"".concat(l,"-progress"))})]}));if(h)return(0,x.cloneElement)(g,j,(0,r.jsx)(k.Z,{mt:0}));if("running"!==o.state)return(0,x.cloneElement)(g,j,(0,r.jsx)(_.Z,{sx:{color:R.UZ,height:"100%",width:"auto"}}));let t="1";if(v&&p){t="0.4";let{unit:n,value:s}=(0,G._J)(m-v);e=(0,r.jsxs)(y.Ac,{position:"absolute",children:["Updated ~",s," ",n," ago"]})}let s=null==c?void 0:c.screenshot;return s&&({sx:n,...s}=s),(0,x.cloneElement)(g,j,(0,r.jsx)(a.Z,{alt:"".concat(N()(o.state),". Preview unavailable"),component:"img",src:"data:image;base64,".concat(f),sx:U()({color:R.s7,fontFamily:"Roboto Condensed",height:f?"100%":"auto",opacity:t,width:"auto"},n),...s}),e)},[h,m,f,o.jobs,o.state,null==c?void 0:c.screenshot,p,v,g,j]);return(0,x.useMemo)(()=>{let e;let n="running"!==o.state||!!o.jobs,t=null==c?void 0:c.button;return t&&({sx:e,...t}=t),(0,x.createElement)(E.Z,{disabled:n,href:u,onClick:l,sx:U()({padding:0,width:"calc(100% - 0em)"},e),...t},C)},[C,l,u,o.jobs,o.state,null==c?void 0:c.button])},K=function(){for(var e=arguments.length,n=Array(e),t=0;t<e;t++)n[t]=arguments[t];let[s]=n,{children:l,getHeader:o=e=>{let{name:n}=e;return(0,r.jsx)(y.Ac,{children:n})},server:c,showControls:i=!0,slotProps:a}=s;return(0,r.jsxs)(b.Lg,{mb:0,mt:0,...null==a?void 0:a.panel,children:[(0,r.jsxs)(b.CH,{...null==a?void 0:a.header,children:[o(c),i&&(0,r.jsx)(Z.Z,{iconButtonProps:{size:"small"},serverName:c.name,serverState:c.state,serverUuid:c.uuid})]}),l]})}},54420:function(e,n,t){t.d(n,{Z:function(){return m}});var r=t(85893),s=t(37737),l=t(90642),o=t(67294),c=t(28937),i=t(86142),a=t(46194),u=t(16667),d=t(37600),h=e=>{let{children:n,containedButtonProps:t,iconButtonProps:s,muiMenuProps:c,onButtonClick:h,onItemClick:x,variant:f="icon",...v}=e,[m,p]=(0,o.useState)(null),g=(0,o.useMemo)(()=>!!m,[m]),j=(0,o.useMemo)(()=>n||("icon"===f?(0,r.jsx)(i.Z,{fontSize:null==s?void 0:s.size}):"Options"),[n,null==s?void 0:s.size,f]),C=(0,o.useCallback)(function(){for(var e=arguments.length,n=Array(e),t=0;t<e;t++)n[t]=arguments[t];let{0:{currentTarget:r}}=n;return p(r),null==h?void 0:h.call(null,...n)},[h]),b=(0,o.useMemo)(()=>"contained"===f?(0,r.jsx)(a.Z,{onClick:C,...t,children:j}):(0,r.jsx)(u.Z,{onClick:C,...s,children:j}),[C,j,t,s,f]),Z=(0,o.useCallback)(function(e,n){for(var t=arguments.length,r=Array(t>2?t-2:0),s=2;s<t;s++)r[s-2]=arguments[s];return p(null),null==x?void 0:x.call(null,e,n,...r)},[x]);return(0,r.jsxs)(l.Z,{children:[b,(0,r.jsx)(d.Z,{muiMenuProps:{anchorEl:m,keepMounted:!0,onClose:()=>p(null),...c},onItemClick:Z,open:g,...v})]})},x=t(11100),f=t(57882),v=t(40657),m=e=>{var n;let{getItemDisabled:t,items:i,onItemClick:u,renderItem:d,serverName:m,serverState:p,serverUuid:g,...j}=e,{confirmDialog:C,setConfirmDialogOpen:b,setConfirmDialogProps:Z,finishConfirm:k}=(0,v.Z)(),y=(0,o.useMemo)(()=>({"force-off":{colour:"red",description:(0,r.jsx)(r.Fragment,{children:"This is equal to pulling the power cord, which may cause data loss or system corruption."}),label:"Force off",path:"/command/stop-server/".concat(g,"?force=1")},"power-off":{description:(0,r.jsx)(r.Fragment,{children:"This is equal to pushing the power button. If the server doesn't respond to the corresponding signals, you may have to manually shut it down."}),label:"Power off",path:"/command/stop-server/".concat(g)},"power-on":{description:(0,r.jsx)(r.Fragment,{children:"This is equal to pushing the power button."}),label:"Power on",path:"/command/start-server/".concat(g)}}),[g]);return(0,r.jsxs)(l.Z,{children:[(0,r.jsx)(h,{getItemDisabled:e=>"running"===p===e.includes("on"),items:y,onItemClick:(e,n)=>{let{colour:t,description:s,label:l,path:o}=n,i=l.toLocaleLowerCase();Z({actionProceedText:l,content:(0,r.jsx)(f.Ac,{children:s}),onProceedAppend:()=>{Z(e=>({...e,loading:!0})),c.Z.put(o).then(()=>{k("Success",{children:(0,r.jsxs)(r.Fragment,{children:["Successfully registered ",i," job on ",m,"."]})})}).catch(e=>{let n=(0,x.Z)(e);n.children=(0,r.jsxs)(r.Fragment,{children:["Failed to register ",i," job on ",m,"; CAUSE:"," ",n.children,"."]}),k("Error",n)})},proceedColour:t,titleText:"".concat(l," server ").concat(m,"?")}),b(!0)},renderItem:(e,n)=>{let t;let{colour:s,label:l}=n;return s&&(t=a.D[s]),(0,r.jsx)(f.Ac,{inheritColour:!0,color:t,children:l})},...j,children:(0,r.jsx)(s.Z,{fontSize:null==j?void 0:null===(n=j.iconButtonProps)||void 0===n?void 0:n.size})}),C]})}},99246:function(e,n,t){var r=t(67294);n.Z=()=>{let e=(0,r.useRef)(!0);return e.current?(e.current=!1,!0):e.current}},22700:function(e,n){n.Z=e=>{let{allocated:n,available:t,reserved:r,total:s}=e,l=BigInt(n);return{allocated:l,available:BigInt(t),reserved:BigInt(r),total:BigInt(s)}}},60665:function(e,n){n.Z=e=>{let{storage_groups:n,total_free:t,total_size:r}=e,s=BigInt(t),l=BigInt(r);return n.reduce((e,n)=>{let{storage_group_free:t,storage_group_name:r,storage_group_total:s,storage_group_uuid:l}=n,o=BigInt(t),c=BigInt(s);return e.storageGroups[l]={free:o,name:r,size:c,used:c-o,uuid:l},e},{storageGroups:{},totalFree:s,totalSize:l,totalUsed:l-s})}}}]);