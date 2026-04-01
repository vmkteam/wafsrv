package challenge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Branding holds customizable page branding.
type Branding struct {
	Title        string
	CompanyName  string
	PrimaryColor string
	SupportURL   string
}

// Captcha provider widget configuration.
type providerWidget struct {
	ScriptURL string
	DivClass  string
}

var providers = map[string]providerWidget{
	"turnstile": {
		ScriptURL: "https://challenges.cloudflare.com/turnstile/v0/api.js",
		DivClass:  "cf-turnstile",
	},
	"hcaptcha": {
		ScriptURL: "https://js.hcaptcha.com/1/api.js",
		DivClass:  "h-captcha",
	},
	"pow": {
		ScriptURL: "",
		DivClass:  "pow-widget",
	},
}

// RenderCaptcha writes a captcha challenge page (HTTP 499).
func RenderCaptcha(w http.ResponseWriter, statusCode int, provider, siteKey, cookieName, requestID string, branding Branding) {
	title := branding.Title
	if title == "" {
		title = "Security Check"
	}

	color := branding.PrimaryColor
	if color == "" {
		color = "#4F46E5"
	}

	pw := providers[provider]
	if pw.ScriptURL == "" {
		pw = providers["turnstile"] // fallback
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f9fafb}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:2rem;max-width:400px;width:100%%;text-align:center}
h1{color:#111827;font-size:1.25rem;margin-bottom:.5rem}
p{color:#6b7280;font-size:.875rem;margin-bottom:1.5rem}
.widget{min-height:65px;display:flex;align-items:center;justify-content:center}
.bar{height:4px;background:%s;border-radius:2px;position:fixed;top:0;left:0;right:0}
.rid{color:#9ca3af;font-size:.75rem;margin-top:.5rem;font-family:monospace}
</style>
<script src="%s" async defer></script>
</head>
<body>
<div class="bar"></div>
<div class="card">
<h1>%s</h1>
<p>Please verify you are human</p>
<div class="widget">
<div class="%s" data-sitekey="%s" data-callback="onPass"></div>
</div>
<p class="rid">%s</p>
</div>
<script>
function onPass(token){
 document.cookie="%s="+token+";path=/;max-age=1800;samesite=lax";
 location.reload();
}
</script>
</body>
</html>`, title, color, pw.ScriptURL, title, pw.DivClass, siteKey, requestID, cookieName)
}

// RenderPowCaptcha writes a PoW challenge page (HTTP 499).
func RenderPowCaptcha(w http.ResponseWriter, statusCode int, ch PowChallenge, cookieName, requestID string, timeout time.Duration, branding Branding) {
	title := branding.Title
	if title == "" {
		title = "Security Check"
	}

	color := branding.PrimaryColor
	if color == "" {
		color = "#4F46E5"
	}

	challengeJSON, _ := json.Marshal(ch)
	timeoutMs := int(timeout / time.Millisecond)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f9fafb}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:2rem;max-width:400px;width:100%%;text-align:center}
h1{color:#111827;font-size:1.25rem;margin-bottom:.5rem}
p{color:#6b7280;font-size:.875rem;margin-bottom:1rem}
.progress{height:4px;background:#e5e7eb;border-radius:2px;overflow:hidden;margin:1rem 0}
.bar{height:100%%;background:%s;border-radius:2px;width:0%%;transition:width .2s}
.status{color:#6b7280;font-size:.75rem}
.rid{color:#9ca3af;font-size:.75rem;margin-top:.5rem;font-family:monospace}
.top{height:4px;background:%s;border-radius:2px;position:fixed;top:0;left:0;right:0}
</style>
</head>
<body>
<div class="top"></div>
<div class="card">
<h1>%s</h1>
<p>Verifying your browser, please wait...</p>
<div class="progress"><div class="bar" id="bar"></div></div>
<p class="status" id="status">Working...</p>
<p class="rid">%s</p>
</div>
<script>
(function(){
var C=%s;
var cookieName="%s";
var timeout=%d;
var w=new Worker(URL.createObjectURL(new Blob(['('+function(){
self.onmessage=function(e){
var d=e.data,s=d.salt,mx=d.maxNumber,ch=d.challenge;
var enc=new TextEncoder();
function hex(buf){for(var h="",a=new Uint8Array(buf),i=0;i<a.length;i++)h+=a[i].toString(16).padStart(2,"0");return h}
var i=0;
function batch(){
var end=Math.min(i+5000,mx+1);
var promises=[];
for(;i<end;i++){
(function(n){
promises.push(crypto.subtle.digest("SHA-256",enc.encode(s+n)).then(function(h2){return{n:n,h:hex(h2)}}));
})(i);
}
Promise.all(promises).then(function(results){
for(var j=0;j<results.length;j++){
if(results[j].h===ch){self.postMessage({found:true,number:results[j].n});return}
}
self.postMessage({progress:i/(mx+1)});
if(i<=mx)batch();
else self.postMessage({found:false});
});
}
batch();
};
}.toString()+')()'],{type:"application/javascript"})));
w.onmessage=function(e){
if(e.data.progress!==undefined){document.getElementById("bar").style.width=(e.data.progress*100)+"%%";return}
if(e.data.found){
document.getElementById("status").textContent="Verified!";
document.getElementById("bar").style.width="100%%";
var p=btoa(JSON.stringify({algorithm:C.algorithm,challenge:C.challenge,number:e.data.number,salt:C.salt,signature:C.signature}));
document.cookie=cookieName+"="+p+";path=/;max-age=60;samesite=lax";
setTimeout(function(){location.reload()},200);
}else{document.getElementById("status").textContent="Verification failed. Please refresh the page."}
};
w.postMessage(C);
setTimeout(function(){w.terminate();document.getElementById("status").textContent="Timeout. Please refresh the page."},timeout);
})();
</script>
</body>
</html>`, title, color, color, title, requestID, challengeJSON, cookieName, timeoutMs)
}

// RenderBlock writes a block page (HTTP 403).
func RenderBlock(w http.ResponseWriter, statusCode int, requestID string, branding Branding) {
	title := branding.Title
	if title == "" {
		title = "Access Denied"
	}

	color := branding.PrimaryColor
	if color == "" {
		color = "#EF4444"
	}

	supportHTML := ""
	if branding.SupportURL != "" {
		supportHTML = fmt.Sprintf(`<p><a href="%s" style="color:%s">Contact support</a></p>`, branding.SupportURL, color)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f9fafb}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:2rem;max-width:400px;width:100%%;text-align:center}
h1{color:#111827;font-size:1.25rem;margin-bottom:.5rem}
p{color:#6b7280;font-size:.875rem;margin-bottom:1rem}
.bar{height:4px;background:%s;border-radius:2px;position:fixed;top:0;left:0;right:0}
.rid{color:#9ca3af;font-size:.75rem;margin-top:.5rem;font-family:monospace}
</style>
</head>
<body>
<div class="bar"></div>
<div class="card">
<h1>%s</h1>
<p>Your request has been blocked.</p>
%s
<p class="rid">%s</p>
</div>
</body>
</html>`, title, color, title, supportHTML, requestID)
}
