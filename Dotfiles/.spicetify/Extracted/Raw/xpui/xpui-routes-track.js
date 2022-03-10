"use strict";(("undefined"!=typeof self?self:global).webpackChunkopen=("undefined"!=typeof self?self:global).webpackChunkopen||[]).push([[730],{44137:(e,n,i)=>{i.d(n,{QN:()=>l});var a=i(98984);const d={kind:"Document",definitions:[{kind:"OperationDefinition",operation:"query",name:{kind:"Name",value:"getTrack"},variableDefinitions:[{kind:"VariableDefinition",variable:{kind:"Variable",name:{kind:"Name",value:"uri"}},type:{kind:"NonNullType",type:{kind:"NamedType",name:{kind:"Name",value:"ID"}}}}],selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"trackUnion"},arguments:[{kind:"Argument",name:{kind:"Name",value:"uri"},value:{kind:"Variable",name:{kind:"Name",value:"uri"}}}],selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"trackFields"}},{kind:"FragmentSpread",name:{kind:"Name",value:"trackNotFound"}}]}}]}},{kind:"FragmentDefinition",name:{kind:"Name",value:"trackFields"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Track"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"uri"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"contentRating"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"label"}}]}},{kind:"Field",name:{kind:"Name",value:"duration"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"totalMilliseconds"}}]}},{kind:"Field",name:{kind:"Name",value:"playability"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"playable"}},{kind:"Field",name:{kind:"Name",value:"reason"}}]}},{kind:"Field",name:{kind:"Name",value:"trackNumber"}},{kind:"Field",name:{kind:"Name",value:"playcount"}},{kind:"Field",name:{kind:"Name",value:"saved"}},{kind:"Field",name:{kind:"Name",value:"sharingInfo"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"shareUrl"}},{kind:"Field",name:{kind:"Name",value:"shareId"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"trackArtists"}},{kind:"FragmentSpread",name:{kind:"Name",value:"trackAlbum"}}]}},{kind:"FragmentDefinition",name:{kind:"Name",value:"trackArtists"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Track"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"artistsWithRoles"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"totalCount"}},{kind:"Field",name:{kind:"Name",value:"items"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"role"}},{kind:"Field",name:{kind:"Name",value:"artist"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"uri"}},{kind:"Field",name:{kind:"Name",value:"visuals"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"avatarImage"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"sources"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"width"}},{kind:"Field",name:{kind:"Name",value:"height"}},{kind:"Field",name:{kind:"Name",value:"url"}}]}}]}}]}},{kind:"Field",name:{kind:"Name",value:"profile"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"name"}}]}}]}}]}}]}}]}},{kind:"FragmentDefinition",name:{kind:"Name",value:"trackAlbum"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Track"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"album"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"uri"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"date"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"isoString"}},{kind:"Field",name:{kind:"Name",value:"precision"}}]}},{kind:"Field",name:{kind:"Name",value:"copyright"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"totalCount"}},{kind:"Field",name:{kind:"Name",value:"items"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"text"}},{kind:"Field",name:{kind:"Name",value:"type"}}]}}]}},{kind:"Field",name:{kind:"Name",value:"courtesyLine"}},{kind:"FragmentSpread",name:{kind:"Name",value:"trackAlbumCoverArt"}}]}}]}},{kind:"FragmentDefinition",name:{kind:"Name",value:"trackAlbumCoverArt"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Album"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"coverArt"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"extractedColors"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"colorRaw"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"hex"}}]}}]}},{kind:"Field",name:{kind:"Name",value:"sources"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"url"}},{kind:"Field",name:{kind:"Name",value:"width"}},{kind:"Field",name:{kind:"Name",value:"height"}}]}}]}}]}},{kind:"FragmentDefinition",name:{kind:"Name",value:"trackNotFound"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"NotFound"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"message"}}]}}]},l=(e,n)=>(0,a.a)(d,e,n)},22845:(e,n,i)=>{i.r(n),i.d(n,{TrackContainer:()=>v,default:()=>N});var a=i(67294),d=i.n(a),l=i(65858),t=i(69518),k=i.n(t),m=i(29255),o=i(23716),s=i(61202),c=i(44137),u=i(72138),r=i(98984);const v=d().memo((()=>{var e;const n=(0,s.k6)(),i=(0,s.TH)(),d=(0,a.useContext)(u.ZF),t=(0,o.g)(),{trackId:v}=(0,s.UO)(),{isAnonymous:N}=(0,l.v9)(m.Gg),S=new URLSearchParams(i.search).get("context"),F=k().trackURI(v).toURI(),p=(0,c.QN)({uri:F},{cacheTime:30*r.y}),g=(0,a.useCallback)(((e,i)=>{var a;const d=t.getState(),l=`${null===(a=k().from(i))||void 0===a?void 0:a.toURLPath(!0)}?highlight=${F}`;N?n.push(l):(d&&!d.isPaused||e>-1&&t.play({uri:i},{featureIdentifier:"track",referrerIdentifier:"deeplink"},{skipTo:{index:e}}),n.replace(l))}),[n,N,t,F]),y=(0,a.useCallback)((()=>{var e;if(p.loading||null===(e=p.data)||void 0===e||!e.trackUnion)return;const n=p.data.trackUnion;g(n.trackNumber-1,n.album.uri)}),[g,null==p||null===(e=p.data)||void 0===e?void 0:e.trackUnion,p.loading]);return(0,a.useEffect)((()=>{const e=k().isPlaylistV1OrV2(S);S&&e?d.getContents(S).then((e=>{const n=e.items.findIndex((e=>(null==e?void 0:e.uri)===F));n<0?y():g(n,S)})):y()}),[S,y,g,d,F]),null})),N=v}}]);
//# sourceMappingURL=xpui-routes-track.js.map