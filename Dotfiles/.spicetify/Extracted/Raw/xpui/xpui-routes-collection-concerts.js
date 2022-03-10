"use strict";(("undefined"!=typeof self?self:global).webpackChunkopen=("undefined"!=typeof self?self:global).webpackChunkopen||[]).push([[835],{40165:(e,t,a)=>{a.r(t),a.d(t,{CollectionConcerts:()=>x,default:()=>J});var n=a(67294),c=a.n(n),o=a(73012),r=a(17231),l=a(44503),i=a(1663),s=a(19565),m=a(6581),u=a(65858),g=a(20657),d=a(42922),h=a(42273),_=a(59482),E=a(72907),y=a(18245),v=a(51574),b=a(7679),p=a(19480);const f="FqqGmylJTvbVkjiIX2eL",L="BUGk_fxRbfJzRml1EewP",N="F9Va5nmgay71lz4V2GLN";var k=a(31595),C=a(70369);const D={Online:g.ag.get("concerts_upcoming_virtual_events"),Recommended:g.ag.get("concerts_recommended_for_you"),Popular:g.ag.get("concerts_popular_near_you"),Playlists:g.ag.get("playlists")},S=o.jN0,w=e=>{const{collection:t,concertMetadata:a,handleLocationChange:n,shouldCombineRecs:o}=e,r=(null==t?void 0:t.items)||[],l=null==t?void 0:t.isFetching,m=a.userLocation.name||g.ag.get("concerts.default_location"),u=e=>{if(!e.concerts||!e.concerts.length)return null;const t=e.concerts[0];return c().createElement(b.k,{key:t.uri,entity:t,isVirtual:o?"ONLINE"===t.category:"online"===e.source,shouldCombineRecs:o})};if(l)return c().createElement(i.h,{errorMessage:g.ag.get("error.request-browse-concerts-failure")});return c().createElement("div",{className:N},c().createElement("div",{className:f,"data-testid":"location-selector"},c().createElement(y.Z,{handleLocationChange:n,locationStr:m})),(()=>{if(!r.length)return c().createElement(s.u,{title:g.ag.get("concerts.error.no_concerts_found_title"),message:g.ag.get("concerts.error.no_concerts_found_message",m)});const e=r.reduce(((e,t)=>("recommendation"===t.source?e.Recommended.push(t):"popular"===t.source?e.Popular.push(t):"online"===t.source&&e.Online.push(t),e)),{Online:[],Recommended:[],Popular:[]});return Object.keys(e).map(((t,a)=>{const n=e[t];return 0===n.length?null:c().createElement("div",{key:t,className:f},c().createElement(d.ZP,{value:"headered-grid",index:a},c().createElement(p.P,{total:n.length,title:D[t],showAll:!0},n.map(u))))}))})())},I=c().memo((()=>{const e=(0,u.I0)(),t=(0,r.W6)(l.AW),a=(0,u.v9)((e=>e.concerts.collection)),o=(0,u.v9)((e=>e.concerts)),i=o.userLocation.name||g.ag.get("concerts.default_location");(0,n.useEffect)((()=>{e((0,m.AJ)(null))}),[e,i]);const s=(0,k.Y)(S);return c().createElement("section",{className:L},c().createElement(C.$,null,`${g.ag.get("concerts_shows_in")} ${i}`),c().createElement(h.gF,{size:h.fR.SMALL,backgroundColor:S},c().createElement(h.sP,null,c().createElement(h.xd,null,g.ag.get("concerts.label"))),c().createElement(_.W,null,c().createElement(E.i,{text:g.ag.get("concerts.label")}))),c().createElement(v.I,{backgroundColor:s}),c().createElement(w,{collection:a,concertMetadata:o,handleLocationChange:t=>{t&&t.geonameId&&e((0,m.AJ)(t.geonameId))},shouldCombineRecs:t}))})),x=e=>c().createElement(n.Suspense,{fallback:null},c().createElement(I,e)),J=x},7679:(e,t,a)=>{a.d(t,{k:()=>N});var n=a(67294),c=a.n(n),o=a(25340),r=a(67892),l=a(94880),i=a(76343);const s="lKqKagNqQ8VlvdFmruT3",m="Z2uK7sMMyCWb6pniuNXi",u="NIMwRV_NRJ13Vqumxn_j",g="t5KPIGEuuRNJCJOxPA1o",d="_32BBOf0wCFJBS35JKFU0",h="vdvOAp_f8lhHOp7y1BqJ",_="qHSZnGIgaXfml2KOzmbd",E="zX69m46sU0G_VEwc4Fiy",y="lKkeD_aRHPt1Sb7cc031",v="hBa5HsnSqAQj7ngrUaoq",b="WD2YMKFx0lQZSbihWLOR";var p=a(43315),f=a(97493),L=a(64656);const N=c().memo((e=>{const{entity:t,isVirtual:a,shouldCombineRecs:n}=e,{venue:{name:N,location:{name:k}}}=t,C=t.artists[0],D=(0,o.ij)(t),S=new Date(t.date.isoString),w=a?f.q:L.K;return c().createElement(r.r,{to:`/concert/${t.id}`,className:s},C.imageUri?c().createElement(l.Z,null,c().createElement("div",{"data-testid":"image-container",className:b,style:{backgroundImage:`linear-gradient(180deg, rgba(18, 18, 18, 0) 0%, rgba(6, 6, 6, 0.6) 60%, rgba(0, 0, 0, 0.7) 100%), url(${C.imageUri})`}})):null,c().createElement("time",{className:m,dateTime:t.date.isoString},c().createElement(i.Dy.h5,{variant:i.$e.minuetBold,className:u},(0,o.lJ)(S)),c().createElement(i.Dy.h1,{variant:i.$e.canon,className:g},S.getDate())),c().createElement("div",{className:d,dir:"auto"},c().createElement(i.Dy.h2,{className:v,variant:i.$e.minuetBold},(0,p.FO)(S),", ",(0,o.b8)(S)),c().createElement(i.Dy.h2,{variant:i.$e.cello,weight:i.vS.bold,className:h},D),c().createElement("div",{className:_},n?c().createElement(w,{className:E,"aria-label":a?"Virtual Event":"In-Person Event",iconSize:16}):null,c().createElement(i.Dy.h2,{className:y,variant:i.$e.mesto,"data-testid":"location-name"},a?N:`${N}, ${k}`))))}))},18245:(e,t,a)=>{a.d(t,{Z:()=>f});a(45697);var n=a(67294),c=a.n(n),o=a(40160),r=a(94184),l=a.n(r),i=a(29854),s=a(20657),m=a(80624),u=a(25237),g=a(98742),d=a(76343);const h={locationContainer:"bH2kPQ5zw1hLCwpWXGGy",locationName:"CZHxaQ5LgtirQvf9Unjx",clearSuggestions:"nPmfHJAB2cFMM9BekCcp",hide:"WmgD8cdy4nG4XBNIO7wJ",changeLocation:"dmmS1BV6JiIcwmD5oTzk",changeLocationDropdown:"n3vaiTuGhBV97WsJ6Zmk",changeLocationInputLabel:"C6NHL3DpQg1P_Kn17nRQ",changeLocationInput:"GLw2a0iCnksbb95n9Uxb",searchInputSearchIcon:"bZEIsokqSuv6PC6x9yPI",changeLocationLabel:"xvdlJPLpxB3UU8F2BDUl",icon:"ZjO209jguit9txCu59ou",changeLocationList:"nfDD3WtVxTUJoHe_XqKs",changeLocationError:"V8EzYUuVJXyfFjyw9Gyz",changeLocationLink:"yJ0x9sVyyDY_aN8Zgu4i",changeLocationItem:"o5i4vbKhh1lViFIVgOc9",button:"qDHCmOVcAjUHggyCn8D4",locationLink:"tc9UlCgbKbc9J2Jtj63x"};var _=a(86912),E=a(8455);const y="location_no_results",v="location_fetch_error",b={[y]:s.ag.get("concert.error.no_locations_found_subtitle"),[v]:s.ag.get("concert.error.general_error_title")},p=e=>{const t=c().createRef(),a=c().createRef(),[r,p]=(0,n.useState)(""),[f,L]=(0,n.useState)(-1),[N,k]=(0,n.useState)([]),[C,D]=(0,n.useState)(null),{placeholder:S,onSelectLocation:w,hideLocationSelector:I}=e,x=(0,i.D)((()=>{u.LH.fetchLocationQuery(m.b.getInstance(),r).then((e=>{const{body:{results:t=[]}={}}=e;k(t),t.length?D(null):D(y)}),(()=>{k([]),D(v)}))}))(250),J=e=>{p(e),L(-1),k([]),D(null),e&&e.length>1&&x(e)};let O=l()(h.clearSuggestions,h.hide);return(N&&N.length||C===y)&&(O=h.clearSuggestions),c().createElement("div",{className:h.changeLocation,"data-interaction-context":"location-selector"},c().createElement("div",{className:h.changeLocationDropdown,onKeyDown:e=>{const n=38,c=40,o=27,r=9,l=e.which;let i=f;switch([o,c,n,r].indexOf(l)>-1&&e.preventDefault(),l){default:return;case o:return void w(null);case n:i=Math.max(f-1,-1);break;case c:case r:i=Math.min(f+1,N.length-1);break;case 13:w(N[f])}if(i<0)t.current.focus();else{const e=a.current.childNodes[i];e&&e.focus()}L(i)},role:"searchbox",onBlur:e=>{e.relatedTarget||(J(""),I())}},c().createElement("div",{className:h.changeLocationForm},c().createElement("div",{className:h.changeLocationLabel},c().createElement(_.z,{className:h.icon,iconSize:16}),c().createElement("input",{className:h.changeLocationInput,type:"search",id:"change-location-input",placeholder:S,value:r,onChange:e=>J(e.target.value),ref:t,"aria-label":S,autoFocus:!0}),c().createElement("button",{className:O,"aria-label":s.ag.get("search.a11y.clear-input"),onClick:()=>J("")},c().createElement(g.T,{size:16})))),c().createElement("ol",{className:h.changeLocationList,ref:a},C&&c().createElement(d.Dy.li,{className:h.changeLocationError},c().createElement(E.Z,{iconSize:16}),b[C]),N&&N.length&&N.map(((e,t)=>c().createElement(d.Dy.li,{weight:d.vS.book,key:t,className:h.changeLocationItem,tabIndex:t+1},c().createElement(o.rU,{to:"#",className:h.changeLocationLink,onClick:()=>w(e),role:"button"},e.location))))||null)))},f=e=>{const{handleLocationChange:t,locationStr:a}=e,[o,r]=(0,n.useState)(!1);return c().createElement("div",{className:h.locationContainer},c().createElement(d.Dy.h1,{variant:d.$e.alto},s.ag.get("concerts_shows_in")),c().createElement("span",null,o&&c().createElement(p,{placeholder:s.ag.get("concerts.input.search_placeholder"),onSelectLocation:e=>{t(e),r(!1)},hideLocationSelector:()=>r(!1)}),!o&&c().createElement(d.Dy.h2,{variant:d.$e.alto,className:h.locationName,dir:"auto",onClick:r,role:"button"},a)))}},25340:(e,t,a)=>{a.d(t,{Ms:()=>c,b8:()=>o,lJ:()=>r,NL:()=>l,O1:()=>i,Yl:()=>u,ij:()=>g});var n=a(20657);const c=e=>n.ag.formatDate(e,{weekday:"short",month:"short",day:"numeric"}),o=e=>n.ag.formatDate(e,{hour:"numeric",minute:"numeric"}),r=e=>n.ag.formatDate(e,{month:"short"}).toUpperCase(),l=e=>n.ag.formatDate(e,{month:"short",day:"numeric"}).toUpperCase(),i=e=>e<new Date,s={row:{1:e=>n.ag.get("concert.header.entity_title_1",...e),2:e=>n.ag.get("concert.header.entity_title_2",...e),3:e=>n.ag.get("concert.header.entity_title_3",...e),4:e=>n.ag.get("concert.header.entity_title_4",...e),more:e=>n.ag.get("concert.header.entity_title_more",...e)},entity:{1:e=>n.ag.get("concert.header.upcoming_concert_title_1",...e),2:e=>n.ag.get("concert.header.upcoming_concert_title_2",...e),3:e=>n.ag.get("concert.header.upcoming_concert_title_3",...e),4:e=>n.ag.get("concert.header.upcoming_concert_title_4",...e),more:e=>n.ag.get("concert.header.upcoming_concert_title_more",...e)}},m=(e,t)=>{const a=s[t],n=(e=>{try{var t;return!e.title||!e.festival&&null!==(t=e.artists)&&void 0!==t&&t.length?{artists:e.artists.map((e=>e.name||e.profile.name))}:{title:e.title}}catch(e){return null}})(e);if(n){if(n.title)return n.title;if(n.artists)return n.artists.length>4?a.more(n.artists):a[n.artists.length](n.artists)}return""},u=e=>m(e,"row"),g=e=>m(e,"entity")},70369:(e,t,a)=>{a.d(t,{$:()=>n.$});var n=a(22578)},19565:(e,t,a)=>{a.d(t,{u:()=>_});var n=a(67294),c=a.n(n),o=a(94184),r=a.n(o),l=a(76343),i=a(62890);const s="FvfvGU3jvHRskUU9v9_8",m="Q9AlbZn2EGzy3MTWXa8X",u="mxmxS0y8LiwSs5nueKPT",g="GXxVAveNFStY3pBI_NO4",d="eHcXC2s97InYP7rMNT0H";var h=a(51775);const _=c().memo((e=>{const{children:t,message:a,title:n,linkTitle:o,linkTo:_,onClick:E,renderInline:y=!1}=e,{isXSOnly:v,isSMOnly:b}=(0,h.e)(),p=v||b;return c().createElement("section",{className:r()(s,{[m]:y})},t,c().createElement(l.Dy.h1,{variant:p?l.Dy.cello:l.Dy.alto,className:g},n),c().createElement(l.Dy,{variant:p?l.Dy.mesto:l.Dy.ballad,className:d},a),o&&(_||E)&&c().createElement(i.z,{version:"secondary",className:u,linkTo:_,onClick:E},o))}))}}]);
//# sourceMappingURL=xpui-routes-collection-concerts.js.map