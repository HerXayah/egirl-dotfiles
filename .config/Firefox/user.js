// Style firefox
//user_pref("browser.startup.preXulSkeletonUI", false);
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);
user_pref("svg.context-properties.content.enabled", true);
user_pref("layout.css.color-mix.enabled", true);
user_pref("layout.css.light-dark.enabled", true);
user_pref("browser.tabs.tabMinWidth", 66);
user_pref("browser.tabs.tabClipWidth", 86);
user_pref("fp.tweak.autohide-bookmarks", false);
user_pref("fp.tweak.macos-button", true);
user_pref("fp.tweak.rounded-corners", false);
user_pref("fp.tweak.sidebar-enabled", false);

// disable spell checking
user_pref("layout.spellcheckDefault", 0);
// disable auto install updates
user_pref("app.update.auto", false);
// disable background service to install updates
user_pref("app.update.service.enabled", false);
// open tabs to the right of the current tab
user_pref("browser.tabs.insertAfterCurrent", true);
// enable dark-mode
user_pref("browser.in-content.dark-mode", true);
user_pref("ui.systemUsesDarkTheme", 1);
// disable data collection & crash reports
user_pref("datareporting.healthreport.uploadEnabled", false);
// disable WebRTC leaks
user_pref("media.peerconnection.enabled", false);
// allow search sugggestions in private windows
user_pref("browser.search.suggest.enabled.private", true);
// Disables geolocation and firefox logging geolocation requests.
user_pref("geo.enabled", false);
user_pref("geo.wifi.uri", "");
user_pref("browser.search.geoip.url", "");
// Only send pings if send and receiving host match (same website).
user_pref("browser.send_pings.require_same_host", true);
// Disable telemetry
user_pref("toolkit.telemetry.enabled", false);
// Disable (Windows-only) scheduled task which runs in the background to collect and submit data about the browser
user_pref("default-browser-agent", false);
// Disable Container Tabs
//user_pref("privacy.userContext.enabled",false);
//user_pref("privacy.userContext.ui.enabled",false);
//user_pref("privacy.userContext.newTabContainerOnLeftClick.enabled", false);

user_pref("apz.overscroll.enabled", true); // DEFAULT NON-LINUX
user_pref("general.smoothScroll", true); // DEFAULT
user_pref("general.smoothScroll.msdPhysics.continuousMotionMaxDeltaMS", 12);
user_pref("general.smoothScroll.msdPhysics.enabled", true);
user_pref("general.smoothScroll.msdPhysics.motionBeginSpringConstant", 600);
user_pref("general.smoothScroll.msdPhysics.regularSpringConstant", 650);
user_pref("general.smoothScroll.msdPhysics.slowdownMinDeltaMS", 25);
user_pref("general.smoothScroll.msdPhysics.slowdownMinDeltaRatio", 2.0);
user_pref("general.smoothScroll.msdPhysics.slowdownSpringConstant", 250);
user_pref("general.smoothScroll.currentVelocityWeighting", 1.0);
user_pref("general.smoothScroll.stopDecelerationWeighting", 1.0);
user_pref("mousewheel.default.delta_multiplier_y", 250); // 250-400; adjust this number to your liking

//// Stuff
user_pref("browser.backspace_action", 0);                                                  // o Pressing Backspace does not open previous page [0]
user_pref("browser.urlbar.clickSelectsAll", false);                                        // o Select all url on Click
user_pref("browser.urlbar.trimURLs", false);                                               // o Display all parts of the url in the urlbar
user_pref("browser.urlbar.update2.engineAliasRefresh", true);                              // x Enable Add button in Search engines options
user_pref("browser.xul.error_pages.expert_bad_cert", true);                                // x Display advanced info on Insecure Connection
user_pref("image.animation_mode", "once");                                                 // / GIF loop once - improves perf a lot
user_pref("media.autoplay.blocking_policy", 0);                                            // x Autoplay of HTML5 media policy 1 = new 2 = old [0]
user_pref("media.autoplay.default", 1);                                                    // x Autoplay block all by default [1]
user_pref("mousewheel.with_shift.action", 4);                                              // x Scroll horizontally on Shift+Mousewheel [4]
user_pref("media.memory_cache_max_size", 65536);                                           // x Increase media memory cache [8192]

//// Network
user_pref("network.dns.disablePrefetch", true);                                            // x Disable DNS prefetching


//// Search
user_pref("browser.urlbar.autoFill", false);                                               // x Disable urlbar autofill with domain extension
user_pref("browser.urlbar.speculativeConnect.enabled", false);                             // o Speculative connections from urlbar
user_pref("browser.urlbar.suggest.searches", false);                                       // o Previous searches suggestions
user_pref("browser.urlbar.suggest.engines", false);                                        // o Search engines in the urlbar (tab2search)

user_pref("gfx.canvas.accelerated.cache-items", 4096); // default=2048; alt=8192
user_pref("gfx.canvas.accelerated.cache-size", 512); // default=256; alt=1024
user_pref("gfx.content.skia-font-cache-size", 20); // default=5; Chrome=20
user_pref("browser.cache.jsbc_compression_level", 3);
user_pref("media.cache_readahead_limit", 7200);
user_pref("media.cache_resume_threshold", 3600);
user_pref("network.http.max-connections", 1800);
user_pref("network.http.max-persistent-connections-per-server", 10);
user_pref("network.http.max-urgent-start-excessive-connections-per-host", 5);
user_pref("network.http.pacing.requests.enabled", false);
user_pref("network.dnsCacheExpiration", 3600); // keep entries for 1 hour
user_pref("network.dns.max_high_priority_threads", 8); // default=5
user_pref("network.ssl_tokens_cache_capacity", 10240); // default=2048; more TLS token caching (fast reconnects)
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);