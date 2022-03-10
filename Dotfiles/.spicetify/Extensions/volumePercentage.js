// @ts-check
// NAME: Add Volume Percentage
// AUTHOR: daksh2k
// VERSION: 1.0
// DESCRIPTION: Add the Volume Percentage to the Volume Bar

/// <reference path="../spicetify-cli/globals.d.ts" />
(function addVolumep(){
    const volumeBar = document.querySelector(".volume-bar")
    if (!(volumeBar && Spicetify.Player)){
        setTimeout(addVolumep, 200);
        return;
    }
    const ele = document.createElement("span")
    ele.classList.add("volume-percent")
    ele.setAttribute("style","font-size: 14px; padding-left: 10px")
    
    volumeBar.append(ele)
    volumeBar.style.flex = "0 1 170px"
    
    updatePercentage()
    function updatePercentage(){
        const currVolume = Math.round( (Spicetify.Player?.origin?._volume?._volume ?? Spicetify.Platform?.PlaybackAPI?._volume)  * 100)
        ele.innerText = currVolume==-100 ? `` : `${currVolume}%`
        document.querySelector(".main-connectBar-connectBar")?.style.setProperty('--triangle-position',"229px");
    }
    if(Spicetify.Platform?.PlaybackAPI === undefined) Spicetify.Player.origin._events.addListener("volume",updatePercentage)
    else Spicetify.Platform.PlaybackAPI._events.addListener("volume",updatePercentage)    
})();