"use strict";(("undefined"!=typeof self?self:global).webpackChunkopen=("undefined"!=typeof self?self:global).webpackChunkopen||[]).push([[994],{34725:(e,t,a)=>{a.r(t),a.d(t,{AboutSpotifyModal:()=>x});var n=a(67294),l=a.n(n),o=a(20657),r=a(14466),s=a(85105),c=a(30806);var i=a(25853),u=a(16775);const m="qi0hX8uXrbQyS6tvdDBt",p="WomzHWnDO_yFyjnkd49P",g="R83hOohwVshnd6bEkDO4",d=new Map([["Win32",o.ag.get("desktop-about.platform-win-x86")],["Win32_ARM64",o.ag.get("desktop-about.platform-win-arm-64")],["OSX",o.ag.get("desktop-about.platform-mac-x86")],["OSX_ARM64",o.ag.get("desktop-about.platform-mac-arm-64")],["Linux",o.ag.get("desktop-about.platform-linux")]]),b=o.ag.get("desktop-about.platform-unknown"),E=()=>{var e;const t=(0,n.useRef)(null),{settings:a}=(0,u.r)(),r=function(){const e=(0,n.useContext)(c.z),[t,a]=(0,n.useState)(null);return(0,n.useEffect)((()=>{let t=!0;return e.getVersionInfo().then((e=>{t&&a(e)})),()=>{t=!1}}),[e,a]),t}();if(null===r)return null;const s="1"===a.values.employee,E=s?r.containerBuildType:"",f=null!==(e=d.get(r.containerPlatform))&&void 0!==e?e:b,v=o.ag.get("desktop-about.platform",{employee_build_type:E},{platform:f}),k=o.ag.get("desktop-about.copy-version-info-tooltip");return l().createElement("div",{className:m},l().createElement("div",{className:p,ref:t},l().createElement("div",null,v),l().createElement("div",null,r.containerVersion),s&&l().createElement("div",null,r.uiVersion)),l().createElement("button",{title:k,className:g,onClick:()=>{t.current&&(0,i.v)(t.current.innerText)}},"⎘"))};var f=a(35225),v=a(35291);const k="hbpwhf54ljdKrhNTq4mA",h=()=>{const e=(0,n.useContext)(c.z),t=(0,f.g)(),a=(0,n.useCallback)((()=>{e.prepareUpdate()}),[e]),r=(0,n.useCallback)((()=>{e.applyUpdate()}),[e]);switch(null==t?void 0:t.state){case v.J.UPDATE_AVAILABLE:return l().createElement("div",null,o.ag.get("about.upgrade.pending",t.version)," ",l().createElement("button",{className:k,onClick:a},o.ag.get("about.upgrade.pending_link")));case v.J.UPDATE_PROCESSING:return l().createElement("div",null,o.ag.get("about.upgrade.downloading"));case v.J.UPDATE_READY:return l().createElement("div",null,o.ag.get("about.upgrade.downloaded",t.version)," ",l().createElement("button",{className:k,onClick:r},o.ag.get("about.upgrade.restart_link")));case v.J.UPDATE_NONE:default:return null}};var y=a(98742),C=a(58548);const N="UnLGG6p932k7WyjkB9Vo",_="GSFvITwD84dS2JA62Mtj",O="KlzblASEYfUfaykBFZgM",A="Ifnz1lh1jjvqPqJ4KPo8",D="XF1XXenkrbdAK2rRoxoU";var w=a(65858),S=a(98871),T=a(76343);const x=l().memo((()=>{const e=(0,w.I0)(),{isOpen:t}=(0,w.v9)((e=>e.aboutSpotify)),a=new Date("2022-01-03").getUTCFullYear().toString(),c=(0,n.useCallback)((()=>{e((0,S.se)())}),[e]);return l().createElement(s.Z,{animated:!0,isOpen:t,onRequestClose:c,contentLabel:o.ag.get("about.title_label")},l().createElement("div",{className:N},l().createElement("main",{className:O},l().createElement(r.Z,{noLink:!0,hasText:!0}),l().createElement(E,null),l().createElement(h,null),l().createElement(T.Dy,{as:"div",variant:T.Dy.finale,className:A},l().createElement(C.kf,{source:o.ag.get("about.copyright",a),paragraphClassName:D}))),l().createElement("button",{"aria-label":o.ag.get("close_button_action"),className:_,onClick:c},l().createElement(y.T,{size:24}))))}))},53573:(e,t,a)=>{a.r(t),a.d(t,{default:()=>b,mapDispatchToProps:()=>d});var n=a(67294),l=a.n(n),o=a(65858),r=a(62504),s=a(20657),c=a(85105);const i={container:"uYKs_kQMPOziaeDj877B",content:"i8qeSJJVx4PXb7fsvOTd",licensesFrame:"WhIzm3S3R6Ker3XvpYW6",buttonContainer:"qsKpcFrhrA8KtuTVIN_y"};var u=a(62890),m=a(76343),p=a(73012);const g=({isOpen:e,onClose:t})=>l().createElement(c.Z,{isOpen:e,onRequestClose:t,contentLabel:s.ag.get("licenses.title")},l().createElement("div",{className:i.container},l().createElement("main",{className:i.content},l().createElement(m.Dy,{as:"h1",variant:m.Dy.alto,className:i.header,color:p.ixZ},s.ag.get("licenses.title")),l().createElement("iframe",{className:i.licensesFrame,title:s.ag.get("licenses.title"),src:"/licenses.html"})),l().createElement("div",{className:i.buttonContainer},l().createElement(u.z,{version:"primary",onClick:t},s.ag.get("close_button_action")))));const d=e=>({hide:()=>e((0,r.xh)())}),b=(0,o.$j)((e=>({isOpen:e.licenses.isOpen})),d)((function({isOpen:e,hide:t}){return l().createElement(g,{isOpen:e,onClose:t})}))}}]);
//# sourceMappingURL=xpui-desktop-modals.js.map