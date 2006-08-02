/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/*
	This is a compiled version of Dojo, built for deployment and not for
	development. To get an editable version, please visit:

		http://dojotoolkit.org

	for documentation and information on getting the source.
*/

if(typeof dojo=="undefined"){
var dj_global=this;
function dj_undef(_1,_2){
if(_2==null){
_2=dojo.global();
}
return (typeof _2[_1]=="undefined");
}
if(dj_undef("djConfig",this)){
var djConfig={};
}
if(dj_undef("dojo",this)){
var dojo={};
}
dojo._currentContext=this;
if(!dj_undef("document",dojo._currentContext)){
dojo._currentDocument=this.document;
}
dojo.locale=djConfig.locale;
dojo.version={major:0,minor:0,patch:0,flag:"dev",revision:Number("$Rev: 4898 $".match(/[0-9]+/)[0]),toString:function(){
with(dojo.version){
return major+"."+minor+"."+patch+flag+" ("+revision+")";
}
}};
dojo.evalProp=function(_3,_4,_5){
return (_4&&!dj_undef(_3,_4)?_4[_3]:(_5?(_4[_3]={}):undefined));
};
dojo.parseObjPath=function(_6,_7,_8){
var _9=(_7!=null?_7:dj_global);
var _a=_6.split(".");
var _b=_a.pop();
for(var i=0,l=_a.length;i<l&&_9;i++){
_9=dojo.evalProp(_a[i],_9,_8);
}
return {obj:_9,prop:_b};
};
dojo.evalObjPath=function(_d,_e){
if(typeof _d!="string"){
return dj_global;
}
if(_d.indexOf(".")==-1){
return dojo.evalProp(_d,dj_global,_e);
}
var _f=dojo.parseObjPath(_d,dj_global,_e);
if(_f){
return dojo.evalProp(_f.prop,_f.obj,_e);
}
return null;
};
dojo.global=function(){
return dojo._currentContext;
};
dojo.doc=function(){
return dojo._currentDocument;
};
dojo.body=function(){
return dojo.doc().body||dojo.doc().getElementsByTagName("body")[0];
};
dojo.withGlobal=function(_10,_11,_12){
var _13=dojo._currentDocument;
var _14=dojo._currentContext;
var _15;
try{
dojo._currentContext=_10;
dojo._currentDocument=_10.document;
if(_12){
_15=dojo.lang.curryArguments(_12,_11,arguments,3);
}else{
_15=_11();
}
}
catch(e){
dojo._currentContext=_14;
dojo._currentDocument=_13;
throw e;
}
dojo._currentContext=_14;
dojo._currentDocument=_13;
return _15;
};
dojo.withDoc=function(_16,_17,_18){
var _19=this._currentDocument;
var _1a;
try{
dojo._currentDocument=_16;
if(_18){
_1a=dojo.lang.curryArguments(_18,_17,arguments,3);
}else{
_1a=_17();
}
}
catch(e){
dojo._currentDocument=_19;
throw e;
}
dojo._currentDocument=_19;
return _1a;
};
dojo.errorToString=function(_1b){
if(!dj_undef("message",_1b)){
return _1b.message;
}else{
if(!dj_undef("description",_1b)){
return _1b.description;
}else{
return _1b;
}
}
};
dojo.raise=function(_1c,_1d){
if(_1d){
_1c=_1c+": "+dojo.errorToString(_1d);
}
try{
dojo.hostenv.println("FATAL: "+_1c);
}
catch(e){
}
throw Error(_1c);
};
dojo.debug=function(){
};
dojo.debugShallow=function(obj){
};
dojo.profile={start:function(){
},end:function(){
},stop:function(){
},dump:function(){
}};
function dj_eval(_1f){
return dj_global.eval?dj_global.eval(_1f):eval(_1f);
}
dojo.unimplemented=function(_20,_21){
var _22="'"+_20+"' not implemented";
if(_21!=null){
_22+=" "+_21;
}
dojo.raise(_22);
};
dojo.deprecated=function(_23,_24,_25){
var _26="DEPRECATED: "+_23;
if(_24){
_26+=" "+_24;
}
if(_25){
_26+=" -- will be removed in version: "+_25;
}
dojo.debug(_26);
};
dojo.inherits=function(_27,_28){
if(typeof _28!="function"){
dojo.raise("dojo.inherits: superclass argument ["+_28+"] must be a function (subclass: ["+_27+"']");
}
_27.prototype=new _28();
_27.prototype.constructor=_27;
_27.superclass=_28.prototype;
_27["super"]=_28.prototype;
};
dojo._mixin=function(obj,_2a){
var _2b={};
for(var x in _2a){
if(typeof _2b[x]=="undefined"||_2b[x]!=_2a[x]){
obj[x]=_2a[x];
}
}
if(dojo.render.html.ie&&dojo.lang.isFunction(_2a["toString"])&&_2a["toString"]!=obj["toString"]){
obj.toString=_2a.toString;
}
return obj;
};
dojo.mixin=function(obj,_2e){
for(var i=1,l=arguments.length;i<l;i++){
dojo._mixin(obj,arguments[i]);
}
return obj;
};
dojo.extend=function(_30,_31){
for(var i=1,l=arguments.length;i<l;i++){
dojo._mixin(_30.prototype,arguments[i]);
}
return _30;
};
dojo.render=(function(){
function vscaffold(_33,_34){
var tmp={capable:false,support:{builtin:false,plugin:false},prefixes:_33};
for(var i=0;i<_34.length;i++){
tmp[_34[i]]=false;
}
return tmp;
}
return {name:"",ver:dojo.version,os:{win:false,linux:false,osx:false},html:vscaffold(["html"],["ie","opera","khtml","safari","moz"]),svg:vscaffold(["svg"],["corel","adobe","batik"]),vml:vscaffold(["vml"],["ie"]),swf:vscaffold(["Swf","Flash","Mm"],["mm"]),swt:vscaffold(["Swt"],["ibm"])};
})();
dojo.hostenv=(function(){
var _37={isDebug:false,allowQueryConfig:false,baseScriptUri:"",baseRelativePath:"",libraryScriptUri:"",iePreventClobber:false,ieClobberMinimal:true,preventBackButtonFix:true,searchIds:[],parseWidgets:true};
if(typeof djConfig=="undefined"){
djConfig=_37;
}else{
for(var _38 in _37){
if(typeof djConfig[_38]=="undefined"){
djConfig[_38]=_37[_38];
}
}
}
return {name_:"(unset)",version_:"(unset)",getName:function(){
return this.name_;
},getVersion:function(){
return this.version_;
},getText:function(uri){
dojo.unimplemented("getText","uri="+uri);
}};
})();
dojo.hostenv.getBaseScriptUri=function(){
if(djConfig.baseScriptUri.length){
return djConfig.baseScriptUri;
}
var uri=new String(djConfig.libraryScriptUri||djConfig.baseRelativePath);
if(!uri){
dojo.raise("Nothing returned by getLibraryScriptUri(): "+uri);
}
var _3b=uri.lastIndexOf("/");
djConfig.baseScriptUri=djConfig.baseRelativePath;
return djConfig.baseScriptUri;
};
(function(){
var _3c={pkgFileName:"__package__",loading_modules_:{},loaded_modules_:{},addedToLoadingCount:[],removedFromLoadingCount:[],inFlightCount:0,modulePrefixes_:{dojo:{name:"dojo",value:"src"}},setModulePrefix:function(_3d,_3e){
this.modulePrefixes_[_3d]={name:_3d,value:_3e};
},getModulePrefix:function(_3f){
var mp=this.modulePrefixes_;
if((mp[_3f])&&(mp[_3f]["name"])){
return mp[_3f].value;
}
return _3f;
},getTextStack:[],loadUriStack:[],loadedUris:[],post_load_:false,modulesLoadedListeners:[],unloadListeners:[],loadNotifying:false};
for(var _41 in _3c){
dojo.hostenv[_41]=_3c[_41];
}
})();
dojo.hostenv.loadPath=function(_42,_43,cb){
var uri;
if((_42.charAt(0)=="/")||(_42.match(/^\w+:/))){
uri=_42;
}else{
uri=this.getBaseScriptUri()+_42;
}
if(djConfig.cacheBust&&dojo.render.html.capable){
uri+="?"+String(djConfig.cacheBust).replace(/\W+/g,"");
}
try{
return ((!_43)?this.loadUri(uri,cb):this.loadUriAndCheck(uri,_43,cb));
}
catch(e){
dojo.debug(e);
return false;
}
};
dojo.hostenv.loadUri=function(uri,cb){
if(this.loadedUris[uri]){
return 1;
}
var _48=this.getText(uri,null,true);
if(_48==null){
return 0;
}
this.loadedUris[uri]=true;
if(cb){
_48="("+_48+")";
}
var _49=dj_eval(_48);
if(cb){
cb(_49);
}
return 1;
};
dojo.hostenv.loadUriAndCheck=function(uri,_4b,cb){
var ok=true;
try{
ok=this.loadUri(uri,cb);
}
catch(e){
dojo.debug("failed loading ",uri," with error: ",e);
}
return ((ok)&&(this.findModule(_4b,false)))?true:false;
};
dojo.loaded=function(){
};
dojo.unloaded=function(){
};
dojo.hostenv.loaded=function(){
this.loadNotifying=true;
this.post_load_=true;
var mll=this.modulesLoadedListeners;
for(var x=0;x<mll.length;x++){
mll[x]();
}
this.modulesLoadedListeners=[];
this.loadNotifying=false;
dojo.loaded();
};
dojo.hostenv.unloaded=function(){
var mll=this.unloadListeners;
while(mll.length){
(mll.pop())();
}
dojo.unloaded();
};
dojo.addOnLoad=function(obj,_52){
var dh=dojo.hostenv;
if(arguments.length==1){
dh.modulesLoadedListeners.push(obj);
}else{
if(arguments.length>1){
dh.modulesLoadedListeners.push(function(){
obj[_52]();
});
}
}
if(dh.post_load_&&dh.inFlightCount==0&&!dh.loadNotifying){
dh.callLoaded();
}
};
dojo.addOnUnload=function(obj,_55){
var dh=dojo.hostenv;
if(arguments.length==1){
dh.unloadListeners.push(obj);
}else{
if(arguments.length>1){
dh.unloadListeners.push(function(){
obj[_55]();
});
}
}
};
dojo.hostenv.modulesLoaded=function(){
if(this.post_load_){
return;
}
if((this.loadUriStack.length==0)&&(this.getTextStack.length==0)){
if(this.inFlightCount>0){
dojo.debug("files still in flight!");
return;
}
dojo.hostenv.callLoaded();
}
};
dojo.hostenv.callLoaded=function(){
if(typeof setTimeout=="object"){
setTimeout("dojo.hostenv.loaded();",0);
}else{
dojo.hostenv.loaded();
}
};
dojo.hostenv.getModuleSymbols=function(_57){
var _58=_57.split(".");
for(var i=_58.length-1;i>0;i--){
var _5a=_58.slice(0,i).join(".");
var _5b=this.getModulePrefix(_5a);
if(_5b!=_5a){
_58.splice(0,i,_5b);
break;
}
}
return _58;
};
dojo._namespaces={};
(function(){
var _5c={};
var _5d={};
dojo.getNamespace=function(_5e){
if(!dojo._namespaces[_5e]&&!_5d[_5e]){
var req=dojo.require;
var _60="dojo.namespaces."+_5e;
if(!_5c[_60]){
_5c[_60]=true;
req(_60,false,true);
_5c[_60]=false;
if(!dojo._namespaces[_5e]){
_5d[_5e]=true;
}
}
}
return dojo._namespaces[_5e];
};
})();
dojo.hostenv._global_omit_module_check=false;
dojo.hostenv.loadModule=function(_61,_62,_63){
if(!_61){
return;
}
_63=this._global_omit_module_check||_63;
var _64=this.findModule(_61,false);
if(_64){
return _64;
}
if(dj_undef(_61,this.loading_modules_)){
this.addedToLoadingCount.push(_61);
}
this.loading_modules_[_61]=1;
var _65=_61.replace(/\./g,"/")+".js";
var _66=_61.split(".");
if(djConfig.autoLoadNamespace){
dojo.getNamespace(_66[0]);
}
var _67=this.getModuleSymbols(_61);
var _68=((_67[0].charAt(0)!="/")&&(!_67[0].match(/^\w+:/)));
var _69=_67[_67.length-1];
if(_69=="*"){
_61=(_66.slice(0,-1)).join(".");
while(_67.length){
_67.pop();
_67.push(this.pkgFileName);
_65=_67.join("/")+".js";
if(_68&&(_65.charAt(0)=="/")){
_65=_65.slice(1);
}
ok=this.loadPath(_65,((!_63)?_61:null));
if(ok){
break;
}
_67.pop();
}
}else{
_65=_67.join("/")+".js";
_61=_66.join(".");
var ok=this.loadPath(_65,((!_63)?_61:null));
if((!ok)&&(!_62)){
_67.pop();
while(_67.length){
_65=_67.join("/")+".js";
ok=this.loadPath(_65,((!_63)?_61:null));
if(ok){
break;
}
_67.pop();
_65=_67.join("/")+"/"+this.pkgFileName+".js";
if(_68&&(_65.charAt(0)=="/")){
_65=_65.slice(1);
}
ok=this.loadPath(_65,((!_63)?_61:null));
if(ok){
break;
}
}
}
if((!ok)&&(!_63)){
dojo.raise("Could not load '"+_61+"'; last tried '"+_65+"'");
}
}
if(!_63&&!this["isXDomain"]){
_64=this.findModule(_61,false);
if(!_64){
dojo.raise("symbol '"+_61+"' is not defined after loading '"+_65+"'");
}
}
return _64;
};
dojo.hostenv.startPackage=function(_6b){
var _6c=dojo.evalObjPath((_6b.split(".").slice(0,-1)).join("."));
this.loaded_modules_[(new String(_6b)).toLowerCase()]=_6c;
var _6d=_6b.split(/\./);
if(_6d[_6d.length-1]=="*"){
_6d.pop();
}
return dojo.evalObjPath(_6d.join("."),true);
};
dojo.hostenv.findModule=function(_6e,_6f){
var lmn=(new String(_6e)).toLowerCase();
if(this.loaded_modules_[lmn]){
return this.loaded_modules_[lmn];
}
var _71=dojo.evalObjPath(_6e);
if((_6e)&&(typeof _71!="undefined")&&(_71)){
this.loaded_modules_[lmn]=_71;
return _71;
}
if(_6f){
dojo.raise("no loaded module named '"+_6e+"'");
}
return null;
};
dojo.kwCompoundRequire=function(_72){
var _73=_72["common"]||[];
var _74=(_72[dojo.hostenv.name_])?_73.concat(_72[dojo.hostenv.name_]||[]):_73.concat(_72["default"]||[]);
for(var x=0;x<_74.length;x++){
var _76=_74[x];
if(_76.constructor==Array){
dojo.hostenv.loadModule.apply(dojo.hostenv,_76);
}else{
dojo.hostenv.loadModule(_76);
}
}
};
dojo.require=function(){
dojo.hostenv.loadModule.apply(dojo.hostenv,arguments);
};
dojo.requireIf=function(){
if((arguments[0]===true)||(arguments[0]=="common")||(arguments[0]&&dojo.render[arguments[0]].capable)){
var _77=[];
for(var i=1;i<arguments.length;i++){
_77.push(arguments[i]);
}
dojo.require.apply(dojo,_77);
}
};
dojo.requireAfterIf=dojo.requireIf;
dojo.provide=function(){
return dojo.hostenv.startPackage.apply(dojo.hostenv,arguments);
};
dojo.setModulePrefix=function(_79,_7a){
return dojo.hostenv.setModulePrefix(_79,_7a);
};
dojo.exists=function(obj,_7c){
var p=_7c.split(".");
for(var i=0;i<p.length;i++){
if(!(obj[p[i]])){
return false;
}
obj=obj[p[i]];
}
return true;
};
}
if(typeof window=="undefined"){
dojo.raise("no window object");
}
(function(){
if(djConfig.allowQueryConfig){
var _7f=document.location.toString();
var _80=_7f.split("?",2);
if(_80.length>1){
var _81=_80[1];
var _82=_81.split("&");
for(var x in _82){
var sp=_82[x].split("=");
if((sp[0].length>9)&&(sp[0].substr(0,9)=="djConfig.")){
var opt=sp[0].substr(9);
try{
djConfig[opt]=eval(sp[1]);
}
catch(e){
djConfig[opt]=sp[1];
}
}
}
}
}
if(((djConfig["baseScriptUri"]=="")||(djConfig["baseRelativePath"]==""))&&(document&&document.getElementsByTagName)){
var _86=document.getElementsByTagName("script");
var _87=/(__package__|dojo|bootstrap1)\.js([\?\.]|$)/i;
for(var i=0;i<_86.length;i++){
var src=_86[i].getAttribute("src");
if(!src){
continue;
}
var m=src.match(_87);
if(m){
var _8b=src.substring(0,m.index);
if(src.indexOf("bootstrap1")>-1){
_8b+="../";
}
if(!this["djConfig"]){
djConfig={};
}
if(djConfig["baseScriptUri"]==""){
djConfig["baseScriptUri"]=_8b;
}
if(djConfig["baseRelativePath"]==""){
djConfig["baseRelativePath"]=_8b;
}
break;
}
}
}
var dr=dojo.render;
var drh=dojo.render.html;
var drs=dojo.render.svg;
var dua=(drh.UA=navigator.userAgent);
var dav=(drh.AV=navigator.appVersion);
var t=true;
var f=false;
drh.capable=t;
drh.support.builtin=t;
dr.ver=parseFloat(drh.AV);
dr.os.mac=dav.indexOf("Macintosh")>=0;
dr.os.win=dav.indexOf("Windows")>=0;
dr.os.linux=dav.indexOf("X11")>=0;
drh.opera=dua.indexOf("Opera")>=0;
drh.khtml=(dav.indexOf("Konqueror")>=0)||(dav.indexOf("Safari")>=0);
drh.safari=dav.indexOf("Safari")>=0;
var _93=dua.indexOf("Gecko");
drh.mozilla=drh.moz=(_93>=0)&&(!drh.khtml);
if(drh.mozilla){
drh.geckoVersion=dua.substring(_93+6,_93+14);
}
drh.ie=(document.all)&&(!drh.opera);
drh.ie50=drh.ie&&dav.indexOf("MSIE 5.0")>=0;
drh.ie55=drh.ie&&dav.indexOf("MSIE 5.5")>=0;
drh.ie60=drh.ie&&dav.indexOf("MSIE 6.0")>=0;
drh.ie70=drh.ie&&dav.indexOf("MSIE 7.0")>=0;
dojo.locale=dojo.locale||(drh.ie?navigator.userLanguage:navigator.language).toLowerCase();
dr.vml.capable=drh.ie;
drs.capable=f;
drs.support.plugin=f;
drs.support.builtin=f;
if(document.implementation&&document.implementation.hasFeature&&document.implementation.hasFeature("org.w3c.dom.svg","1.0")){
drs.capable=t;
drs.support.builtin=t;
drs.support.plugin=f;
}
})();
dojo.hostenv.startPackage("dojo.hostenv");
dojo.render.name=dojo.hostenv.name_="browser";
dojo.hostenv.searchIds=[];
dojo.hostenv._XMLHTTP_PROGIDS=["Msxml2.XMLHTTP","Microsoft.XMLHTTP","Msxml2.XMLHTTP.4.0"];
dojo.hostenv.getXmlhttpObject=function(){
var _94=null;
var _95=null;
try{
_94=new XMLHttpRequest();
}
catch(e){
}
if(!_94){
for(var i=0;i<3;++i){
var _97=dojo.hostenv._XMLHTTP_PROGIDS[i];
try{
_94=new ActiveXObject(_97);
}
catch(e){
_95=e;
}
if(_94){
dojo.hostenv._XMLHTTP_PROGIDS=[_97];
break;
}
}
}
if(!_94){
return dojo.raise("XMLHTTP not available",_95);
}
return _94;
};
dojo.hostenv._blockAsync=false;
dojo.hostenv.getText=function(uri,_99,_9a){
if(!_99){
this._blockAsync=true;
}
var _9b=this.getXmlhttpObject();
function isDocumentOk(_9c){
var _9d=_9c["status"];
return Boolean((!_9d)||((200<=_9d)&&(300>_9d))||(_9d==304));
}
if(_99){
var _9e=this,timer=null,gbl=dojo.global();
var xhr=dojo.evalObjPath("dojo.io.XMLHTTPTransport");
_9b.onreadystatechange=function(){
if(timer){
gbl.clearTimeout(timer);
timer=null;
}
if(_9e._blockAsync||(xhr&&xhr._blockAsync)){
timer=gbl.setTimeout(function(){
_9b.onreadystatechange.apply(this);
},10);
}else{
if(4==_9b.readyState){
if(isDocumentOk(_9b)){
_99(_9b.responseText);
}
}
}
};
}
_9b.open("GET",uri,_99?true:false);
try{
_9b.send(null);
if(_99){
return null;
}
if(!isDocumentOk(_9b)){
var err=Error("Unable to load "+uri+" status:"+_9b.status);
err.status=_9b.status;
err.responseText=_9b.responseText;
throw err;
}
}
catch(e){
this._blockAsync=false;
if((_9a)&&(!_99)){
return null;
}else{
throw e;
}
}
this._blockAsync=false;
return _9b.responseText;
};
dojo.hostenv.defaultDebugContainerId="dojoDebug";
dojo.hostenv._println_buffer=[];
dojo.hostenv._println_safe=false;
dojo.hostenv.println=function(_a1){
if(!dojo.hostenv._println_safe){
dojo.hostenv._println_buffer.push(_a1);
}else{
try{
var _a2=document.getElementById(djConfig.debugContainerId?djConfig.debugContainerId:dojo.hostenv.defaultDebugContainerId);
if(!_a2){
_a2=dojo.body();
}
var div=document.createElement("div");
div.appendChild(document.createTextNode(_a1));
_a2.appendChild(div);
}
catch(e){
try{
document.write("<div>"+_a1+"</div>");
}
catch(e2){
window.status=_a1;
}
}
}
};
dojo.addOnLoad(function(){
dojo.hostenv._println_safe=true;
while(dojo.hostenv._println_buffer.length>0){
dojo.hostenv.println(dojo.hostenv._println_buffer.shift());
}
});
function dj_addNodeEvtHdlr(_a4,_a5,fp,_a7){
var _a8=_a4["on"+_a5]||function(){
};
_a4["on"+_a5]=function(){
fp.apply(_a4,arguments);
_a8.apply(_a4,arguments);
};
return true;
}
dj_addNodeEvtHdlr(window,"load",function(){
if(arguments.callee.initialized){
return;
}
arguments.callee.initialized=true;
var _a9=function(){
if(dojo.render.html.ie){
dojo.hostenv.makeWidgets();
}
};
if(dojo.hostenv.inFlightCount==0){
_a9();
dojo.hostenv.modulesLoaded();
}else{
dojo.addOnLoad(_a9);
}
});
dj_addNodeEvtHdlr(window,"unload",function(){
dojo.hostenv.unloaded();
});
dojo.hostenv.makeWidgets=function(){
var _aa=[];
if(djConfig.searchIds&&djConfig.searchIds.length>0){
_aa=_aa.concat(djConfig.searchIds);
}
if(dojo.hostenv.searchIds&&dojo.hostenv.searchIds.length>0){
_aa=_aa.concat(dojo.hostenv.searchIds);
}
if((djConfig.parseWidgets)||(_aa.length>0)){
if(dojo.evalObjPath("dojo.widget.Parse")){
var _ab=new dojo.xml.Parse();
if(_aa.length>0){
for(var x=0;x<_aa.length;x++){
var _ad=document.getElementById(_aa[x]);
if(!_ad){
continue;
}
var _ae=_ab.parseElement(_ad,null,true);
dojo.widget.getParser().createComponents(_ae);
}
}else{
if(djConfig.parseWidgets){
var _ae=_ab.parseElement(dojo.body(),null,true);
dojo.widget.getParser().createComponents(_ae);
}
}
}
}
};
dojo.addOnLoad(function(){
if(!dojo.render.html.ie){
dojo.hostenv.makeWidgets();
}
});
try{
if(dojo.render.html.ie){
document.namespaces.add("v","urn:schemas-microsoft-com:vml");
document.createStyleSheet().addRule("v\\:*","behavior:url(#default#VML)");
}
}
catch(e){
}
dojo.hostenv.writeIncludes=function(){
};
dojo.byId=function(id,doc){
if(id&&(typeof id=="string"||id instanceof String)){
if(!doc){
doc=dojo.doc();
}
return doc.getElementById(id);
}
return id;
};
(function(){
if(typeof dj_usingBootstrap!="undefined"){
return;
}
var _b1=false;
var _b2=false;
var _b3=false;
if((typeof this["load"]=="function")&&((typeof this["Packages"]=="function")||(typeof this["Packages"]=="object"))){
_b1=true;
}else{
if(typeof this["load"]=="function"){
_b2=true;
}else{
if(window.widget){
_b3=true;
}
}
}
var _b4=[];
if((this["djConfig"])&&((djConfig["isDebug"])||(djConfig["debugAtAllCosts"]))){
_b4.push("debug.js");
}
if((this["djConfig"])&&(djConfig["debugAtAllCosts"])&&(!_b1)&&(!_b3)){
_b4.push("browser_debug.js");
}
if((this["djConfig"])&&(djConfig["compat"])){
_b4.push("compat/"+djConfig["compat"]+".js");
}
var _b5=djConfig["baseScriptUri"];
if((this["djConfig"])&&(djConfig["baseLoaderUri"])){
_b5=djConfig["baseLoaderUri"];
}
for(var x=0;x<_b4.length;x++){
var _b7=_b5+"src/"+_b4[x];
if(_b1||_b2){
load(_b7);
}else{
try{
document.write("<scr"+"ipt type='text/javascript' src='"+_b7+"'></scr"+"ipt>");
}
catch(e){
var _b8=document.createElement("script");
_b8.src=_b7;
document.getElementsByTagName("head")[0].appendChild(_b8);
}
}
}
})();
dojo.normalizeLocale=function(_b9){
return _b9?_b9.toLowerCase():dojo.locale;
};
dojo.requireLocalization=function(_ba,_bb,_bc){
var _bd=dojo.hostenv.getModuleSymbols(_ba);
var _be=_bd.concat("nls").join("/");
_bc=dojo.normalizeLocale(_bc);
var _bf=_bc.split("-");
var _c0=[];
for(var i=_bf.length;i>0;i--){
_c0.push(_bf.slice(0,i).join("-"));
}
_c0.push(false);
var _c2=[_ba,"_nls",_bb].join(".");
var _c3=dojo.hostenv.startPackage(_c2);
dojo.hostenv.loaded_modules_[_c2]=_c3;
var _c4=false;
for(var j=_c0.length-1;j>=0;j--){
var loc=_c0[j]||"ROOT";
var pkg=_c2+"."+loc;
var _c8=false;
if(!dojo.hostenv.findModule(pkg)){
dojo.hostenv.loaded_modules_[pkg]=null;
var _c9=[_be];
if(_c0[j]){
_c9.push(loc);
}
_c9.push(_bb);
var _ca=_c9.join("/")+".js";
_c8=dojo.hostenv.loadPath(_ca,null,function(_cb){
var _cc=function(){
};
_cc.prototype=_c4;
_c3[loc]=new _cc();
for(var k in _cb){
_c3[loc][k]=_cb[k];
}
});
}else{
_c8=true;
}
if(_c8&&_c3[loc]){
_c4=_c3[loc];
}
}
};
(function(){
var _ce=djConfig.extraLocale;
if(_ce){
var req=dojo.requireLocalization;
dojo.requireLocalization=function(m,b,_d2){
req(m,b,_d2);
if(_d2){
return;
}
if(_ce instanceof Array){
for(var i=0;i<_ce.length;i++){
req(m,b,_ce[i]);
}
}else{
req(m,b,_ce);
}
};
}
})();
dojo.provide("dojo.dom");
dojo.dom.ELEMENT_NODE=1;
dojo.dom.ATTRIBUTE_NODE=2;
dojo.dom.TEXT_NODE=3;
dojo.dom.CDATA_SECTION_NODE=4;
dojo.dom.ENTITY_REFERENCE_NODE=5;
dojo.dom.ENTITY_NODE=6;
dojo.dom.PROCESSING_INSTRUCTION_NODE=7;
dojo.dom.COMMENT_NODE=8;
dojo.dom.DOCUMENT_NODE=9;
dojo.dom.DOCUMENT_TYPE_NODE=10;
dojo.dom.DOCUMENT_FRAGMENT_NODE=11;
dojo.dom.NOTATION_NODE=12;
dojo.dom.dojoml="http://www.dojotoolkit.org/2004/dojoml";
dojo.dom.xmlns={svg:"http://www.w3.org/2000/svg",smil:"http://www.w3.org/2001/SMIL20/",mml:"http://www.w3.org/1998/Math/MathML",cml:"http://www.xml-cml.org",xlink:"http://www.w3.org/1999/xlink",xhtml:"http://www.w3.org/1999/xhtml",xul:"http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul",xbl:"http://www.mozilla.org/xbl",fo:"http://www.w3.org/1999/XSL/Format",xsl:"http://www.w3.org/1999/XSL/Transform",xslt:"http://www.w3.org/1999/XSL/Transform",xi:"http://www.w3.org/2001/XInclude",xforms:"http://www.w3.org/2002/01/xforms",saxon:"http://icl.com/saxon",xalan:"http://xml.apache.org/xslt",xsd:"http://www.w3.org/2001/XMLSchema",dt:"http://www.w3.org/2001/XMLSchema-datatypes",xsi:"http://www.w3.org/2001/XMLSchema-instance",rdf:"http://www.w3.org/1999/02/22-rdf-syntax-ns#",rdfs:"http://www.w3.org/2000/01/rdf-schema#",dc:"http://purl.org/dc/elements/1.1/",dcq:"http://purl.org/dc/qualifiers/1.0","soap-env":"http://schemas.xmlsoap.org/soap/envelope/",wsdl:"http://schemas.xmlsoap.org/wsdl/",AdobeExtensions:"http://ns.adobe.com/AdobeSVGViewerExtensions/3.0/"};
dojo.dom.isNode=function(wh){
if(typeof Element=="function"){
try{
return wh instanceof Element;
}
catch(E){
}
}else{
return wh&&!isNaN(wh.nodeType);
}
};
dojo.dom.getUniqueId=function(){
var _d5=dojo.doc();
do{
var id="dj_unique_"+(++arguments.callee._idIncrement);
}while(_d5.getElementById(id));
return id;
};
dojo.dom.getUniqueId._idIncrement=0;
dojo.dom.firstElement=dojo.dom.getFirstChildElement=function(_d7,_d8){
var _d9=_d7.firstChild;
while(_d9&&_d9.nodeType!=dojo.dom.ELEMENT_NODE){
_d9=_d9.nextSibling;
}
if(_d8&&_d9&&_d9.tagName&&_d9.tagName.toLowerCase()!=_d8.toLowerCase()){
_d9=dojo.dom.nextElement(_d9,_d8);
}
return _d9;
};
dojo.dom.lastElement=dojo.dom.getLastChildElement=function(_da,_db){
var _dc=_da.lastChild;
while(_dc&&_dc.nodeType!=dojo.dom.ELEMENT_NODE){
_dc=_dc.previousSibling;
}
if(_db&&_dc&&_dc.tagName&&_dc.tagName.toLowerCase()!=_db.toLowerCase()){
_dc=dojo.dom.prevElement(_dc,_db);
}
return _dc;
};
dojo.dom.nextElement=dojo.dom.getNextSiblingElement=function(_dd,_de){
if(!_dd){
return null;
}
do{
_dd=_dd.nextSibling;
}while(_dd&&_dd.nodeType!=dojo.dom.ELEMENT_NODE);
if(_dd&&_de&&_de.toLowerCase()!=_dd.tagName.toLowerCase()){
return dojo.dom.nextElement(_dd,_de);
}
return _dd;
};
dojo.dom.prevElement=dojo.dom.getPreviousSiblingElement=function(_df,_e0){
if(!_df){
return null;
}
if(_e0){
_e0=_e0.toLowerCase();
}
do{
_df=_df.previousSibling;
}while(_df&&_df.nodeType!=dojo.dom.ELEMENT_NODE);
if(_df&&_e0&&_e0.toLowerCase()!=_df.tagName.toLowerCase()){
return dojo.dom.prevElement(_df,_e0);
}
return _df;
};
dojo.dom.moveChildren=function(_e1,_e2,_e3){
var _e4=0;
if(_e3){
while(_e1.hasChildNodes()&&_e1.firstChild.nodeType==dojo.dom.TEXT_NODE){
_e1.removeChild(_e1.firstChild);
}
while(_e1.hasChildNodes()&&_e1.lastChild.nodeType==dojo.dom.TEXT_NODE){
_e1.removeChild(_e1.lastChild);
}
}
while(_e1.hasChildNodes()){
_e2.appendChild(_e1.firstChild);
_e4++;
}
return _e4;
};
dojo.dom.copyChildren=function(_e5,_e6,_e7){
var _e8=_e5.cloneNode(true);
return this.moveChildren(_e8,_e6,_e7);
};
dojo.dom.removeChildren=function(_e9){
var _ea=_e9.childNodes.length;
while(_e9.hasChildNodes()){
_e9.removeChild(_e9.firstChild);
}
return _ea;
};
dojo.dom.replaceChildren=function(_eb,_ec){
dojo.dom.removeChildren(_eb);
_eb.appendChild(_ec);
};
dojo.dom.removeNode=function(_ed){
if(_ed&&_ed.parentNode){
return _ed.parentNode.removeChild(_ed);
}
};
dojo.dom.getAncestors=function(_ee,_ef,_f0){
var _f1=[];
var _f2=(_ef&&(_ef instanceof Function||typeof _ef=="function"));
while(_ee){
if(!_f2||_ef(_ee)){
_f1.push(_ee);
}
if(_f0&&_f1.length>0){
return _f1[0];
}
_ee=_ee.parentNode;
}
if(_f0){
return null;
}
return _f1;
};
dojo.dom.getAncestorsByTag=function(_f3,tag,_f5){
tag=tag.toLowerCase();
return dojo.dom.getAncestors(_f3,function(el){
return ((el.tagName)&&(el.tagName.toLowerCase()==tag));
},_f5);
};
dojo.dom.getFirstAncestorByTag=function(_f7,tag){
return dojo.dom.getAncestorsByTag(_f7,tag,true);
};
dojo.dom.isDescendantOf=function(_f9,_fa,_fb){
if(_fb&&_f9){
_f9=_f9.parentNode;
}
while(_f9){
if(_f9==_fa){
return true;
}
_f9=_f9.parentNode;
}
return false;
};
dojo.dom.innerXML=function(_fc){
if(_fc.innerXML){
return _fc.innerXML;
}else{
if(_fc.xml){
return _fc.xml;
}else{
if(typeof XMLSerializer!="undefined"){
return (new XMLSerializer()).serializeToString(_fc);
}
}
}
};
dojo.dom.createDocument=function(){
var doc=null;
var _fe=dojo.doc();
if(!dj_undef("ActiveXObject")){
var _ff=["MSXML2","Microsoft","MSXML","MSXML3"];
for(var i=0;i<_ff.length;i++){
try{
doc=new ActiveXObject(_ff[i]+".XMLDOM");
}
catch(e){
}
if(doc){
break;
}
}
}else{
if((_fe.implementation)&&(_fe.implementation.createDocument)){
doc=_fe.implementation.createDocument("","",null);
}
}
return doc;
};
dojo.dom.createDocumentFromText=function(str,_102){
if(!_102){
_102="text/xml";
}
if(!dj_undef("DOMParser")){
var _103=new DOMParser();
return _103.parseFromString(str,_102);
}else{
if(!dj_undef("ActiveXObject")){
var _104=dojo.dom.createDocument();
if(_104){
_104.async=false;
_104.loadXML(str);
return _104;
}else{
dojo.debug("toXml didn't work?");
}
}else{
var _105=dojo.doc();
if(_105.createElement){
var tmp=_105.createElement("xml");
tmp.innerHTML=str;
if(_105.implementation&&_105.implementation.createDocument){
var _107=_105.implementation.createDocument("foo","",null);
for(var i=0;i<tmp.childNodes.length;i++){
_107.importNode(tmp.childNodes.item(i),true);
}
return _107;
}
return ((tmp.document)&&(tmp.document.firstChild?tmp.document.firstChild:tmp));
}
}
}
return null;
};
dojo.dom.prependChild=function(node,_10a){
if(_10a.firstChild){
_10a.insertBefore(node,_10a.firstChild);
}else{
_10a.appendChild(node);
}
return true;
};
dojo.dom.insertBefore=function(node,ref,_10d){
if(_10d!=true&&(node===ref||node.nextSibling===ref)){
return false;
}
var _10e=ref.parentNode;
_10e.insertBefore(node,ref);
return true;
};
dojo.dom.insertAfter=function(node,ref,_111){
var pn=ref.parentNode;
if(ref==pn.lastChild){
if((_111!=true)&&(node===ref)){
return false;
}
pn.appendChild(node);
}else{
return this.insertBefore(node,ref.nextSibling,_111);
}
return true;
};
dojo.dom.insertAtPosition=function(node,ref,_115){
if((!node)||(!ref)||(!_115)){
return false;
}
switch(_115.toLowerCase()){
case "before":
return dojo.dom.insertBefore(node,ref);
case "after":
return dojo.dom.insertAfter(node,ref);
case "first":
if(ref.firstChild){
return dojo.dom.insertBefore(node,ref.firstChild);
}else{
ref.appendChild(node);
return true;
}
break;
default:
ref.appendChild(node);
return true;
}
};
dojo.dom.insertAtIndex=function(node,_117,_118){
var _119=_117.childNodes;
if(!_119.length){
_117.appendChild(node);
return true;
}
var _11a=null;
for(var i=0;i<_119.length;i++){
var _11c=_119.item(i)["getAttribute"]?parseInt(_119.item(i).getAttribute("dojoinsertionindex")):-1;
if(_11c<_118){
_11a=_119.item(i);
}
}
if(_11a){
return dojo.dom.insertAfter(node,_11a);
}else{
return dojo.dom.insertBefore(node,_119.item(0));
}
};
dojo.dom.textContent=function(node,text){
if(text){
var _11f=dojo.doc();
dojo.dom.replaceChildren(node,_11f.createTextNode(text));
return text;
}else{
var _120="";
if(node==null){
return _120;
}
for(var i=0;i<node.childNodes.length;i++){
switch(node.childNodes[i].nodeType){
case 1:
case 5:
_120+=dojo.dom.textContent(node.childNodes[i]);
break;
case 3:
case 2:
case 4:
_120+=node.childNodes[i].nodeValue;
break;
default:
break;
}
}
return _120;
}
};
dojo.dom.hasParent=function(node){
return node&&node.parentNode&&dojo.dom.isNode(node.parentNode);
};
dojo.dom.isTag=function(node){
if(node&&node.tagName){
for(var i=1;i<arguments.length;i++){
if(node.tagName==String(arguments[i])){
return String(arguments[i]);
}
}
}
return "";
};
dojo.dom.setAttributeNS=function(elem,_126,_127,_128){
if(elem==null||((elem==undefined)&&(typeof elem=="undefined"))){
dojo.raise("No element given to dojo.dom.setAttributeNS");
}
if(!((elem.setAttributeNS==undefined)&&(typeof elem.setAttributeNS=="undefined"))){
elem.setAttributeNS(_126,_127,_128);
}else{
var _129=elem.ownerDocument;
var _12a=_129.createNode(2,_127,_126);
_12a.nodeValue=_128;
elem.setAttributeNode(_12a);
}
};
dojo.provide("dojo.xml.Parse");
dojo.xml.Parse=function(){
function getDojoTagName(node){
var _12c=node.tagName;
if(dojo.render.html.capable&&dojo.render.html.ie&&node.scopeName!="HTML"){
_12c=node.scopeName+":"+_12c;
}
if(_12c.substr(0,5).toLowerCase()=="dojo:"){
return _12c.toLowerCase();
}
if(_12c.substr(0,4).toLowerCase()=="dojo"){
return "dojo:"+_12c.substring(4).toLowerCase();
}
var djt=node.getAttribute("dojoType")||node.getAttribute("dojotype");
if(djt){
if(djt.indexOf(":")<0){
djt="dojo:"+djt;
}
return djt.toLowerCase();
}
if(node.getAttributeNS&&node.getAttributeNS(dojo.dom.dojoml,"type")){
return "dojo:"+node.getAttributeNS(dojo.dom.dojoml,"type").toLowerCase();
}
try{
djt=node.getAttribute("dojo:type");
}
catch(e){
}
if(djt){
return "dojo:"+djt.toLowerCase();
}
if(!dj_global["djConfig"]||!djConfig["ignoreClassNames"]){
var _12e=node.className||node.getAttribute("class");
if(_12e&&_12e.indexOf&&_12e.indexOf("dojo-")!=-1){
var _12f=_12e.split(" ");
for(var x=0;x<_12f.length;x++){
if(_12f[x].length>5&&_12f[x].indexOf("dojo-")>=0){
return "dojo:"+_12f[x].substr(5).toLowerCase();
}
}
}
}
return _12c.toLowerCase();
}
this.parseElement=function(node,_132,_133,_134){
var _135={};
if(node.tagName&&node.tagName.indexOf("/")==0){
return null;
}
var _136=getDojoTagName(node);
_135[_136]=[];
if(_136.substr(0,4).toLowerCase()=="dojo"){
_135.namespace="dojo";
}else{
var pos=_136.indexOf(":");
if(pos>0){
_135.namespace=_136.substring(0,pos);
}
}
var _138=false;
if(!_133){
_138=true;
}else{
if(_135.namespace&&dojo.getNamespace(_135.namespace)){
_138=true;
}else{
if(dojo.widget.tags[_136]){
dojo.deprecated("dojo.xml.Parse.parseElement","Widgets should be placed in a defined namespace","0.5");
_138=true;
}
}
}
if(_138){
var _139=this.parseAttributes(node);
for(var attr in _139){
if((!_135[_136][attr])||(typeof _135[_136][attr]!="array")){
_135[_136][attr]=[];
}
_135[_136][attr].push(_139[attr]);
}
_135[_136].nodeRef=node;
_135.tagName=_136;
_135.index=_134||0;
}
var _13b=0;
for(var i=0;i<node.childNodes.length;i++){
var tcn=node.childNodes.item(i);
switch(tcn.nodeType){
case dojo.dom.ELEMENT_NODE:
_13b++;
var ctn=getDojoTagName(tcn);
if(!_135[ctn]){
_135[ctn]=[];
}
_135[ctn].push(this.parseElement(tcn,true,_133,_13b));
if((tcn.childNodes.length==1)&&(tcn.childNodes.item(0).nodeType==dojo.dom.TEXT_NODE)){
_135[ctn][_135[ctn].length-1].value=tcn.childNodes.item(0).nodeValue;
}
break;
case dojo.dom.TEXT_NODE:
if(node.childNodes.length==1){
_135[_136].push({value:node.childNodes.item(0).nodeValue});
}
break;
default:
break;
}
}
return _135;
};
this.parseAttributes=function(node){
var _140={};
var atts=node.attributes;
var _142,i=0;
while((_142=atts[i++])){
if((dojo.render.html.capable)&&(dojo.render.html.ie)){
if(!_142){
continue;
}
if((typeof _142=="object")&&(typeof _142.nodeValue=="undefined")||(_142.nodeValue==null)||(_142.nodeValue=="")){
continue;
}
}
var nn=_142.nodeName.split(":");
nn=(nn.length==2)?nn[1]:_142.nodeName;
_140[nn]={value:_142.nodeValue};
}
return _140;
};
};
dojo.provide("dojo.lang.common");
dojo.lang._mixin=dojo._mixin;
dojo.lang.mixin=dojo.mixin;
dojo.lang.extend=dojo.extend;
dojo.lang.find=function(_144,_145,_146,_147){
if(!dojo.lang.isArrayLike(_144)&&dojo.lang.isArrayLike(_145)){
dojo.deprecated("dojo.lang.find(value, array)","use dojo.lang.find(array, value) instead","0.5");
var temp=_144;
_144=_145;
_145=temp;
}
var _149=dojo.lang.isString(_144);
if(_149){
_144=_144.split("");
}
if(_147){
var step=-1;
var i=_144.length-1;
var end=-1;
}else{
var step=1;
var i=0;
var end=_144.length;
}
if(_146){
while(i!=end){
if(_144[i]===_145){
return i;
}
i+=step;
}
}else{
while(i!=end){
if(_144[i]==_145){
return i;
}
i+=step;
}
}
return -1;
};
dojo.lang.indexOf=dojo.lang.find;
dojo.lang.findLast=function(_14d,_14e,_14f){
return dojo.lang.find(_14d,_14e,_14f,true);
};
dojo.lang.lastIndexOf=dojo.lang.findLast;
dojo.lang.inArray=function(_150,_151){
return dojo.lang.find(_150,_151)>-1;
};
dojo.lang.isObject=function(it){
if(typeof it=="undefined"){
return false;
}
return (typeof it=="object"||it===null||dojo.lang.isArray(it)||dojo.lang.isFunction(it));
};
dojo.lang.isArray=function(it){
return (it instanceof Array||typeof it=="array");
};
dojo.lang.isArrayLike=function(it){
if(dojo.lang.isString(it)){
return false;
}
if(dojo.lang.isFunction(it)){
return false;
}
if(dojo.lang.isArray(it)){
return true;
}
if(typeof it!="undefined"&&it&&dojo.lang.isNumber(it.length)&&isFinite(it.length)){
return true;
}
return false;
};
dojo.lang.isFunction=function(it){
if(!it){
return false;
}
return (it instanceof Function||typeof it=="function");
};
dojo.lang.isString=function(it){
return (it instanceof String||typeof it=="string");
};
dojo.lang.isAlien=function(it){
if(!it){
return false;
}
return !dojo.lang.isFunction()&&/\{\s*\[native code\]\s*\}/.test(String(it));
};
dojo.lang.isBoolean=function(it){
return (it instanceof Boolean||typeof it=="boolean");
};
dojo.lang.isNumber=function(it){
return (it instanceof Number||typeof it=="number");
};
dojo.lang.isUndefined=function(it){
return ((it==undefined)&&(typeof it=="undefined"));
};
dojo.provide("dojo.lang.func");
dojo.lang.hitch=function(_15b,_15c){
var fcn=dojo.lang.isString(_15c)?_15b[_15c]:_15c;
return function(){
return fcn.apply(_15b,arguments);
};
};
dojo.lang.anonCtr=0;
dojo.lang.anon={};
dojo.lang.nameAnonFunc=function(_15e,_15f,_160){
var nso=(_15f||dojo.lang.anon);
if((_160)||((dj_global["djConfig"])&&(djConfig["slowAnonFuncLookups"]==true))){
for(var x in nso){
try{
if(nso[x]===_15e){
return x;
}
}
catch(e){
}
}
}
var ret="__"+dojo.lang.anonCtr++;
while(typeof nso[ret]!="undefined"){
ret="__"+dojo.lang.anonCtr++;
}
nso[ret]=_15e;
return ret;
};
dojo.lang.forward=function(_164){
return function(){
return this[_164].apply(this,arguments);
};
};
dojo.lang.curry=function(ns,func){
var _167=[];
ns=ns||dj_global;
if(dojo.lang.isString(func)){
func=ns[func];
}
for(var x=2;x<arguments.length;x++){
_167.push(arguments[x]);
}
var _169=(func["__preJoinArity"]||func.length)-_167.length;
function gather(_16a,_16b,_16c){
var _16d=_16c;
var _16e=_16b.slice(0);
for(var x=0;x<_16a.length;x++){
_16e.push(_16a[x]);
}
_16c=_16c-_16a.length;
if(_16c<=0){
var res=func.apply(ns,_16e);
_16c=_16d;
return res;
}else{
return function(){
return gather(arguments,_16e,_16c);
};
}
}
return gather([],_167,_169);
};
dojo.lang.curryArguments=function(ns,func,args,_174){
var _175=[];
var x=_174||0;
for(x=_174;x<args.length;x++){
_175.push(args[x]);
}
return dojo.lang.curry.apply(dojo.lang,[ns,func].concat(_175));
};
dojo.lang.tryThese=function(){
for(var x=0;x<arguments.length;x++){
try{
if(typeof arguments[x]=="function"){
var ret=(arguments[x]());
if(ret){
return ret;
}
}
}
catch(e){
dojo.debug(e);
}
}
};
dojo.lang.delayThese=function(farr,cb,_17b,_17c){
if(!farr.length){
if(typeof _17c=="function"){
_17c();
}
return;
}
if((typeof _17b=="undefined")&&(typeof cb=="number")){
_17b=cb;
cb=function(){
};
}else{
if(!cb){
cb=function(){
};
if(!_17b){
_17b=0;
}
}
}
setTimeout(function(){
(farr.shift())();
cb();
dojo.lang.delayThese(farr,cb,_17b,_17c);
},_17b);
};
dojo.provide("dojo.lang.array");
dojo.lang.has=function(obj,name){
try{
return (typeof obj[name]!="undefined");
}
catch(e){
return false;
}
};
dojo.lang.isEmpty=function(obj){
if(dojo.lang.isObject(obj)){
var tmp={};
var _181=0;
for(var x in obj){
if(obj[x]&&(!tmp[x])){
_181++;
break;
}
}
return (_181==0);
}else{
if(dojo.lang.isArrayLike(obj)||dojo.lang.isString(obj)){
return obj.length==0;
}
}
};
dojo.lang.map=function(arr,obj,_185){
var _186=dojo.lang.isString(arr);
if(_186){
arr=arr.split("");
}
if(dojo.lang.isFunction(obj)&&(!_185)){
_185=obj;
obj=dj_global;
}else{
if(dojo.lang.isFunction(obj)&&_185){
var _187=obj;
obj=_185;
_185=_187;
}
}
if(Array.map){
var _188=Array.map(arr,_185,obj);
}else{
var _188=[];
for(var i=0;i<arr.length;++i){
_188.push(_185.call(obj,arr[i]));
}
}
if(_186){
return _188.join("");
}else{
return _188;
}
};
dojo.lang.forEach=function(_18a,_18b,_18c){
if(dojo.lang.isString(_18a)){
_18a=_18a.split("");
}
if(Array.forEach){
Array.forEach(_18a,_18b,_18c);
}else{
if(!_18c){
_18c=dj_global;
}
for(var i=0,l=_18a.length;i<l;i++){
_18b.call(_18c,_18a[i],i,_18a);
}
}
};
dojo.lang._everyOrSome=function(_18e,arr,_190,_191){
if(dojo.lang.isString(arr)){
arr=arr.split("");
}
if(Array.every){
return Array[(_18e)?"every":"some"](arr,_190,_191);
}else{
if(!_191){
_191=dj_global;
}
for(var i=0,l=arr.length;i<l;i++){
var _193=_190.call(_191,arr[i],i,arr);
if((_18e)&&(!_193)){
return false;
}else{
if((!_18e)&&(_193)){
return true;
}
}
}
return (_18e)?true:false;
}
};
dojo.lang.every=function(arr,_195,_196){
return this._everyOrSome(true,arr,_195,_196);
};
dojo.lang.some=function(arr,_198,_199){
return this._everyOrSome(false,arr,_198,_199);
};
dojo.lang.filter=function(arr,_19b,_19c){
var _19d=dojo.lang.isString(arr);
if(_19d){
arr=arr.split("");
}
if(Array.filter){
var _19e=Array.filter(arr,_19b,_19c);
}else{
if(!_19c){
if(arguments.length>=3){
dojo.raise("thisObject doesn't exist!");
}
_19c=dj_global;
}
var _19e=[];
for(var i=0;i<arr.length;i++){
if(_19b.call(_19c,arr[i],i,arr)){
_19e.push(arr[i]);
}
}
}
if(_19d){
return _19e.join("");
}else{
return _19e;
}
};
dojo.lang.unnest=function(){
var out=[];
for(var i=0;i<arguments.length;i++){
if(dojo.lang.isArrayLike(arguments[i])){
var add=dojo.lang.unnest.apply(this,arguments[i]);
out=out.concat(add);
}else{
out.push(arguments[i]);
}
}
return out;
};
dojo.lang.toArray=function(_1a3,_1a4){
var _1a5=[];
for(var i=_1a4||0;i<_1a3.length;i++){
_1a5.push(_1a3[i]);
}
return _1a5;
};
dojo.provide("dojo.lang.extras");
dojo.lang.setTimeout=function(func,_1a8){
var _1a9=window,argsStart=2;
if(!dojo.lang.isFunction(func)){
_1a9=func;
func=_1a8;
_1a8=arguments[2];
argsStart++;
}
if(dojo.lang.isString(func)){
func=_1a9[func];
}
var args=[];
for(var i=argsStart;i<arguments.length;i++){
args.push(arguments[i]);
}
return dojo.global().setTimeout(function(){
func.apply(_1a9,args);
},_1a8);
};
dojo.lang.clearTimeout=function(_1ac){
dojo.global().clearTimeout(_1ac);
};
dojo.lang.getNameInObj=function(ns,item){
if(!ns){
ns=dj_global;
}
for(var x in ns){
if(ns[x]===item){
return new String(x);
}
}
return null;
};
dojo.lang.shallowCopy=function(obj,deep){
var i,ret;
if(obj===null){
return null;
}
if(dojo.lang.isObject(obj)){
ret=new obj.constructor();
for(i in obj){
if(dojo.lang.isUndefined(ret[i])){
ret[i]=deep?dojo.lang.shallowCopy(obj[i],deep):obj[i];
}
}
}else{
if(dojo.lang.isArray(obj)){
ret=[];
for(i=0;i<obj.length;i++){
ret[i]=deep?dojo.lang.shallowCopy(obj[i],deep):obj[i];
}
}else{
ret=obj;
}
}
return ret;
};
dojo.lang.firstValued=function(){
for(var i=0;i<arguments.length;i++){
if(typeof arguments[i]!="undefined"){
return arguments[i];
}
}
return undefined;
};
dojo.lang.getObjPathValue=function(_1b4,_1b5,_1b6){
with(dojo.parseObjPath(_1b4,_1b5,_1b6)){
return dojo.evalProp(prop,obj,_1b6);
}
};
dojo.lang.setObjPathValue=function(_1b7,_1b8,_1b9,_1ba){
if(arguments.length<4){
_1ba=true;
}
with(dojo.parseObjPath(_1b7,_1b9,_1ba)){
if(obj&&(_1ba||(prop in obj))){
obj[prop]=_1b8;
}
}
};
dojo.provide("dojo.lang.declare");
dojo.lang.declare=function(_1bb,_1bc,init,_1be){
if((dojo.lang.isFunction(_1be))||((!_1be)&&(!dojo.lang.isFunction(init)))){
var temp=_1be;
_1be=init;
init=temp;
}
var _1c0=[];
if(dojo.lang.isArray(_1bc)){
_1c0=_1bc;
_1bc=_1c0.shift();
}
if(!init){
init=dojo.evalObjPath(_1bb,false);
if((init)&&(!dojo.lang.isFunction(init))){
init=null;
}
}
var ctor=dojo.lang.declare._makeConstructor();
var scp=(_1bc?_1bc.prototype:null);
if(scp){
scp.prototyping=true;
ctor.prototype=new _1bc();
scp.prototyping=false;
}
ctor.superclass=scp;
ctor.mixins=_1c0;
for(var i=0,l=_1c0.length;i<l;i++){
dojo.lang.extend(ctor,_1c0[i].prototype);
}
ctor.prototype.initializer=null;
ctor.prototype.declaredClass=_1bb;
if(dojo.lang.isArray(_1be)){
dojo.lang.extend.apply(dojo.lang,[ctor].concat(_1be));
}else{
dojo.lang.extend(ctor,(_1be)||{});
}
dojo.lang.extend(ctor,dojo.lang.declare.base);
ctor.prototype.constructor=ctor;
ctor.prototype.initializer=(ctor.prototype.initializer)||(init)||(function(){
});
dojo.lang.setObjPathValue(_1bb,ctor,null,true);
};
dojo.lang.declare._makeConstructor=function(){
return function(){
var self=this._getPropContext();
var s=self.constructor.superclass;
if((s)&&(s.constructor)){
if(s.constructor==arguments.callee){
this.inherited("constructor",arguments);
}else{
this._inherited(s,"constructor",arguments);
}
}
var m=(self.constructor.mixins)||([]);
for(var i=0,l=m.length;i<l;i++){
(((m[i].prototype)&&(m[i].prototype.initializer))||(m[i])).apply(this,arguments);
}
if((!this.prototyping)&&(self.initializer)){
self.initializer.apply(this,arguments);
}
};
};
dojo.lang.declare.base={_getPropContext:function(){
return (this.___proto||this);
},_inherited:function(_1c8,_1c9,args){
var _1cb=this.___proto;
this.___proto=_1c8;
var _1cc=_1c8[_1c9].apply(this,(args||[]));
this.___proto=_1cb;
return _1cc;
},inheritedFrom:function(ctor,prop,args){
var p=((ctor)&&(ctor.prototype)&&(ctor.prototype[prop]));
return (dojo.lang.isFunction(p)?p.apply(this,(args||[])):p);
},inherited:function(prop,args){
var p=this._getPropContext();
do{
if((!p.constructor)||(!p.constructor.superclass)){
return;
}
p=p.constructor.superclass;
}while(!(prop in p));
return (dojo.lang.isFunction(p[prop])?this._inherited(p,prop,args):p[prop]);
}};
dojo.declare=dojo.lang.declare;
dojo.provide("dojo.event");
dojo.event=new function(){
this.canTimeout=dojo.lang.isFunction(dj_global["setTimeout"])||dojo.lang.isAlien(dj_global["setTimeout"]);
function interpolateArgs(args,_1d5){
var dl=dojo.lang;
var ao={srcObj:dj_global,srcFunc:null,adviceObj:dj_global,adviceFunc:null,aroundObj:null,aroundFunc:null,adviceType:(args.length>2)?args[0]:"after",precedence:"last",once:false,delay:null,rate:0,adviceMsg:false};
switch(args.length){
case 0:
return;
case 1:
return;
case 2:
ao.srcFunc=args[0];
ao.adviceFunc=args[1];
break;
case 3:
if((dl.isObject(args[0]))&&(dl.isString(args[1]))&&(dl.isString(args[2]))){
ao.adviceType="after";
ao.srcObj=args[0];
ao.srcFunc=args[1];
ao.adviceFunc=args[2];
}else{
if((dl.isString(args[1]))&&(dl.isString(args[2]))){
ao.srcFunc=args[1];
ao.adviceFunc=args[2];
}else{
if((dl.isObject(args[0]))&&(dl.isString(args[1]))&&(dl.isFunction(args[2]))){
ao.adviceType="after";
ao.srcObj=args[0];
ao.srcFunc=args[1];
var _1d8=dl.nameAnonFunc(args[2],ao.adviceObj,_1d5);
ao.adviceFunc=_1d8;
}else{
if((dl.isFunction(args[0]))&&(dl.isObject(args[1]))&&(dl.isString(args[2]))){
ao.adviceType="after";
ao.srcObj=dj_global;
var _1d8=dl.nameAnonFunc(args[0],ao.srcObj,_1d5);
ao.srcFunc=_1d8;
ao.adviceObj=args[1];
ao.adviceFunc=args[2];
}
}
}
}
break;
case 4:
if((dl.isObject(args[0]))&&(dl.isObject(args[2]))){
ao.adviceType="after";
ao.srcObj=args[0];
ao.srcFunc=args[1];
ao.adviceObj=args[2];
ao.adviceFunc=args[3];
}else{
if((dl.isString(args[0]))&&(dl.isString(args[1]))&&(dl.isObject(args[2]))){
ao.adviceType=args[0];
ao.srcObj=dj_global;
ao.srcFunc=args[1];
ao.adviceObj=args[2];
ao.adviceFunc=args[3];
}else{
if((dl.isString(args[0]))&&(dl.isFunction(args[1]))&&(dl.isObject(args[2]))){
ao.adviceType=args[0];
ao.srcObj=dj_global;
var _1d8=dl.nameAnonFunc(args[1],dj_global,_1d5);
ao.srcFunc=_1d8;
ao.adviceObj=args[2];
ao.adviceFunc=args[3];
}else{
if((dl.isString(args[0]))&&(dl.isObject(args[1]))&&(dl.isString(args[2]))&&(dl.isFunction(args[3]))){
ao.srcObj=args[1];
ao.srcFunc=args[2];
var _1d8=dl.nameAnonFunc(args[3],dj_global,_1d5);
ao.adviceObj=dj_global;
ao.adviceFunc=_1d8;
}else{
if(dl.isObject(args[1])){
ao.srcObj=args[1];
ao.srcFunc=args[2];
ao.adviceObj=dj_global;
ao.adviceFunc=args[3];
}else{
if(dl.isObject(args[2])){
ao.srcObj=dj_global;
ao.srcFunc=args[1];
ao.adviceObj=args[2];
ao.adviceFunc=args[3];
}else{
ao.srcObj=ao.adviceObj=ao.aroundObj=dj_global;
ao.srcFunc=args[1];
ao.adviceFunc=args[2];
ao.aroundFunc=args[3];
}
}
}
}
}
}
break;
case 6:
ao.srcObj=args[1];
ao.srcFunc=args[2];
ao.adviceObj=args[3];
ao.adviceFunc=args[4];
ao.aroundFunc=args[5];
ao.aroundObj=dj_global;
break;
default:
ao.srcObj=args[1];
ao.srcFunc=args[2];
ao.adviceObj=args[3];
ao.adviceFunc=args[4];
ao.aroundObj=args[5];
ao.aroundFunc=args[6];
ao.once=args[7];
ao.delay=args[8];
ao.rate=args[9];
ao.adviceMsg=args[10];
break;
}
if(dl.isFunction(ao.aroundFunc)){
var _1d8=dl.nameAnonFunc(ao.aroundFunc,ao.aroundObj,_1d5);
ao.aroundFunc=_1d8;
}
if(dl.isFunction(ao.srcFunc)){
ao.srcFunc=dl.getNameInObj(ao.srcObj,ao.srcFunc);
}
if(dl.isFunction(ao.adviceFunc)){
ao.adviceFunc=dl.getNameInObj(ao.adviceObj,ao.adviceFunc);
}
if((ao.aroundObj)&&(dl.isFunction(ao.aroundFunc))){
ao.aroundFunc=dl.getNameInObj(ao.aroundObj,ao.aroundFunc);
}
if(!ao.srcObj){
dojo.raise("bad srcObj for srcFunc: "+ao.srcFunc);
}
if(!ao.adviceObj){
dojo.raise("bad adviceObj for adviceFunc: "+ao.adviceFunc);
}
return ao;
}
this.connect=function(){
if(arguments.length==1){
var ao=arguments[0];
}else{
var ao=interpolateArgs(arguments,true);
}
if(dojo.lang.isArray(ao.srcObj)&&ao.srcObj!=""){
var _1da={};
for(var x in ao){
_1da[x]=ao[x];
}
var mjps=[];
dojo.lang.forEach(ao.srcObj,function(src){
if((dojo.render.html.capable)&&(dojo.lang.isString(src))){
src=dojo.byId(src);
}
_1da.srcObj=src;
mjps.push(dojo.event.connect.call(dojo.event,_1da));
});
return mjps;
}
var mjp=dojo.event.MethodJoinPoint.getForMethod(ao.srcObj,ao.srcFunc);
if(ao.adviceFunc){
var mjp2=dojo.event.MethodJoinPoint.getForMethod(ao.adviceObj,ao.adviceFunc);
}
mjp.kwAddAdvice(ao);
return mjp;
};
this.log=function(a1,a2){
var _1e2;
if((arguments.length==1)&&(typeof a1=="object")){
_1e2=a1;
}else{
_1e2={srcObj:a1,srcFunc:a2};
}
_1e2.adviceFunc=function(){
var _1e3=[];
for(var x=0;x<arguments.length;x++){
_1e3.push(arguments[x]);
}
dojo.debug("("+_1e2.srcObj+")."+_1e2.srcFunc,":",_1e3.join(", "));
};
this.kwConnect(_1e2);
};
this.connectBefore=function(){
var args=["before"];
for(var i=0;i<arguments.length;i++){
args.push(arguments[i]);
}
return this.connect.apply(this,args);
};
this.connectAround=function(){
var args=["around"];
for(var i=0;i<arguments.length;i++){
args.push(arguments[i]);
}
return this.connect.apply(this,args);
};
this.connectOnce=function(){
var ao=interpolateArgs(arguments,true);
ao.once=true;
return this.connect(ao);
};
this._kwConnectImpl=function(_1ea,_1eb){
var fn=(_1eb)?"disconnect":"connect";
if(typeof _1ea["srcFunc"]=="function"){
_1ea.srcObj=_1ea["srcObj"]||dj_global;
var _1ed=dojo.lang.nameAnonFunc(_1ea.srcFunc,_1ea.srcObj,true);
_1ea.srcFunc=_1ed;
}
if(typeof _1ea["adviceFunc"]=="function"){
_1ea.adviceObj=_1ea["adviceObj"]||dj_global;
var _1ed=dojo.lang.nameAnonFunc(_1ea.adviceFunc,_1ea.adviceObj,true);
_1ea.adviceFunc=_1ed;
}
return dojo.event[fn]((_1ea["type"]||_1ea["adviceType"]||"after"),_1ea["srcObj"]||dj_global,_1ea["srcFunc"],_1ea["adviceObj"]||_1ea["targetObj"]||dj_global,_1ea["adviceFunc"]||_1ea["targetFunc"],_1ea["aroundObj"],_1ea["aroundFunc"],_1ea["once"],_1ea["delay"],_1ea["rate"],_1ea["adviceMsg"]||false);
};
this.kwConnect=function(_1ee){
return this._kwConnectImpl(_1ee,false);
};
this.disconnect=function(){
var ao=interpolateArgs(arguments,true);
if(!ao.adviceFunc){
return;
}
var mjp=dojo.event.MethodJoinPoint.getForMethod(ao.srcObj,ao.srcFunc);
return mjp.removeAdvice(ao.adviceObj,ao.adviceFunc,ao.adviceType,ao.once);
};
this.kwDisconnect=function(_1f1){
return this._kwConnectImpl(_1f1,true);
};
};
dojo.event.MethodInvocation=function(_1f2,obj,args){
this.jp_=_1f2;
this.object=obj;
this.args=[];
for(var x=0;x<args.length;x++){
this.args[x]=args[x];
}
this.around_index=-1;
};
dojo.event.MethodInvocation.prototype.proceed=function(){
this.around_index++;
if(this.around_index>=this.jp_.around.length){
return this.jp_.object[this.jp_.methodname].apply(this.jp_.object,this.args);
}else{
var ti=this.jp_.around[this.around_index];
var mobj=ti[0]||dj_global;
var meth=ti[1];
return mobj[meth].call(mobj,this);
}
};
dojo.event.MethodJoinPoint=function(obj,_1fa){
this.object=obj||dj_global;
this.methodname=_1fa;
this.methodfunc=this.object[_1fa];
this.before=[];
this.after=[];
this.around=[];
};
dojo.event.MethodJoinPoint.getForMethod=function(obj,_1fc){
if(!obj){
obj=dj_global;
}
if(!obj[_1fc]){
obj[_1fc]=function(){
};
if(!obj[_1fc]){
dojo.raise("Cannot set do-nothing method on that object "+_1fc);
}
}else{
if((!dojo.lang.isFunction(obj[_1fc]))&&(!dojo.lang.isAlien(obj[_1fc]))){
return null;
}
}
var _1fd=_1fc+"$joinpoint";
var _1fe=_1fc+"$joinpoint$method";
var _1ff=obj[_1fd];
if(!_1ff){
var _200=false;
if(dojo.event["browser"]){
if((obj["attachEvent"])||(obj["nodeType"])||(obj["addEventListener"])){
_200=true;
dojo.event.browser.addClobberNodeAttrs(obj,[_1fd,_1fe,_1fc]);
}
}
var _201=obj[_1fc].length;
obj[_1fe]=obj[_1fc];
_1ff=obj[_1fd]=new dojo.event.MethodJoinPoint(obj,_1fe);
obj[_1fc]=function(){
var args=[];
if((_200)&&(!arguments.length)){
var evt=null;
try{
if(obj.ownerDocument){
evt=obj.ownerDocument.parentWindow.event;
}else{
if(obj.documentElement){
evt=obj.documentElement.ownerDocument.parentWindow.event;
}else{
if(obj.event){
evt=obj.event;
}else{
evt=window.event;
}
}
}
}
catch(e){
evt=window.event;
}
if(evt){
args.push(dojo.event.browser.fixEvent(evt,this));
}
}else{
for(var x=0;x<arguments.length;x++){
if((x==0)&&(_200)&&(dojo.event.browser.isEvent(arguments[x]))){
args.push(dojo.event.browser.fixEvent(arguments[x],this));
}else{
args.push(arguments[x]);
}
}
}
return _1ff.run.apply(_1ff,args);
};
obj[_1fc].__preJoinArity=_201;
}
return _1ff;
};
dojo.lang.extend(dojo.event.MethodJoinPoint,{unintercept:function(){
this.object[this.methodname]=this.methodfunc;
this.before=[];
this.after=[];
this.around=[];
},disconnect:dojo.lang.forward("unintercept"),run:function(){
var obj=this.object||dj_global;
var args=arguments;
var _207=[];
for(var x=0;x<args.length;x++){
_207[x]=args[x];
}
var _209=function(marr){
if(!marr){
dojo.debug("Null argument to unrollAdvice()");
return;
}
var _20b=marr[0]||dj_global;
var _20c=marr[1];
if(!_20b[_20c]){
dojo.raise("function \""+_20c+"\" does not exist on \""+_20b+"\"");
}
var _20d=marr[2]||dj_global;
var _20e=marr[3];
var msg=marr[6];
var _210;
var to={args:[],jp_:this,object:obj,proceed:function(){
return _20b[_20c].apply(_20b,to.args);
}};
to.args=_207;
var _212=parseInt(marr[4]);
var _213=((!isNaN(_212))&&(marr[4]!==null)&&(typeof marr[4]!="undefined"));
if(marr[5]){
var rate=parseInt(marr[5]);
var cur=new Date();
var _216=false;
if((marr["last"])&&((cur-marr.last)<=rate)){
if(dojo.event.canTimeout){
if(marr["delayTimer"]){
clearTimeout(marr.delayTimer);
}
var tod=parseInt(rate*2);
var mcpy=dojo.lang.shallowCopy(marr);
marr.delayTimer=setTimeout(function(){
mcpy[5]=0;
_209(mcpy);
},tod);
}
return;
}else{
marr.last=cur;
}
}
if(_20e){
_20d[_20e].call(_20d,to);
}else{
if((_213)&&((dojo.render.html)||(dojo.render.svg))){
dj_global["setTimeout"](function(){
if(msg){
_20b[_20c].call(_20b,to);
}else{
_20b[_20c].apply(_20b,args);
}
},_212);
}else{
if(msg){
_20b[_20c].call(_20b,to);
}else{
_20b[_20c].apply(_20b,args);
}
}
}
};
if(this.before.length>0){
dojo.lang.forEach(this.before.concat(new Array()),_209);
}
var _219;
if(this.around.length>0){
var mi=new dojo.event.MethodInvocation(this,obj,args);
_219=mi.proceed();
}else{
if(this.methodfunc){
_219=this.object[this.methodname].apply(this.object,args);
}
}
if(this.after.length>0){
dojo.lang.forEach(this.after.concat(new Array()),_209);
}
return (this.methodfunc)?_219:null;
},getArr:function(kind){
var arr=this.after;
if((typeof kind=="string")&&(kind.indexOf("before")!=-1)){
arr=this.before;
}else{
if(kind=="around"){
arr=this.around;
}
}
return arr;
},kwAddAdvice:function(args){
this.addAdvice(args["adviceObj"],args["adviceFunc"],args["aroundObj"],args["aroundFunc"],args["adviceType"],args["precedence"],args["once"],args["delay"],args["rate"],args["adviceMsg"]);
},addAdvice:function(_21e,_21f,_220,_221,_222,_223,once,_225,rate,_227){
var arr=this.getArr(_222);
if(!arr){
dojo.raise("bad this: "+this);
}
var ao=[_21e,_21f,_220,_221,_225,rate,_227];
if(once){
if(this.hasAdvice(_21e,_21f,_222,arr)>=0){
return;
}
}
if(_223=="first"){
arr.unshift(ao);
}else{
arr.push(ao);
}
},hasAdvice:function(_22a,_22b,_22c,arr){
if(!arr){
arr=this.getArr(_22c);
}
var ind=-1;
for(var x=0;x<arr.length;x++){
var aao=(typeof _22b=="object")?(new String(_22b)).toString():_22b;
var a1o=(typeof arr[x][1]=="object")?(new String(arr[x][1])).toString():arr[x][1];
if((arr[x][0]==_22a)&&(a1o==aao)){
ind=x;
}
}
return ind;
},removeAdvice:function(_232,_233,_234,once){
var arr=this.getArr(_234);
var ind=this.hasAdvice(_232,_233,_234,arr);
if(ind==-1){
return false;
}
while(ind!=-1){
arr.splice(ind,1);
if(once){
break;
}
ind=this.hasAdvice(_232,_233,_234,arr);
}
return true;
}});
dojo.provide("dojo.event.topic");
dojo.event.topic=new function(){
this.topics={};
this.getTopic=function(_238){
if(!this.topics[_238]){
this.topics[_238]=new this.TopicImpl(_238);
}
return this.topics[_238];
};
this.registerPublisher=function(_239,obj,_23b){
var _239=this.getTopic(_239);
_239.registerPublisher(obj,_23b);
};
this.subscribe=function(_23c,obj,_23e){
var _23c=this.getTopic(_23c);
_23c.subscribe(obj,_23e);
};
this.unsubscribe=function(_23f,obj,_241){
var _23f=this.getTopic(_23f);
_23f.unsubscribe(obj,_241);
};
this.destroy=function(_242){
this.getTopic(_242).destroy();
delete this.topics[_242];
};
this.publishApply=function(_243,args){
var _243=this.getTopic(_243);
_243.sendMessage.apply(_243,args);
};
this.publish=function(_245,_246){
var _245=this.getTopic(_245);
var args=[];
for(var x=1;x<arguments.length;x++){
args.push(arguments[x]);
}
_245.sendMessage.apply(_245,args);
};
};
dojo.event.topic.TopicImpl=function(_249){
this.topicName=_249;
this.subscribe=function(_24a,_24b){
var tf=_24b||_24a;
var to=(!_24b)?dj_global:_24a;
dojo.event.kwConnect({srcObj:this,srcFunc:"sendMessage",adviceObj:to,adviceFunc:tf});
};
this.unsubscribe=function(_24e,_24f){
var tf=(!_24f)?_24e:_24f;
var to=(!_24f)?null:_24e;
dojo.event.kwDisconnect({srcObj:this,srcFunc:"sendMessage",adviceObj:to,adviceFunc:tf});
};
this.destroy=function(){
dojo.event.MethodJoinPoint.getForMethod(this,"sendMessage").disconnect();
};
this.registerPublisher=function(_252,_253){
dojo.event.connect(_252,_253,this,"sendMessage");
};
this.sendMessage=function(_254){
};
};
dojo.provide("dojo.event.browser");
dojo._ie_clobber=new function(){
this.clobberNodes=[];
function nukeProp(node,prop){
try{
node[prop]=null;
}
catch(e){
}
try{
delete node[prop];
}
catch(e){
}
try{
node.removeAttribute(prop);
}
catch(e){
}
}
this.clobber=function(_257){
var na;
var tna;
if(_257){
tna=_257.all||_257.getElementsByTagName("*");
na=[_257];
for(var x=0;x<tna.length;x++){
if(tna[x]["__doClobber__"]){
na.push(tna[x]);
}
}
}else{
try{
window.onload=null;
}
catch(e){
}
na=(this.clobberNodes.length)?this.clobberNodes:document.all;
}
tna=null;
var _25b={};
for(var i=na.length-1;i>=0;i=i-1){
var el=na[i];
if(el["__clobberAttrs__"]){
for(var j=0;j<el.__clobberAttrs__.length;j++){
nukeProp(el,el.__clobberAttrs__[j]);
}
nukeProp(el,"__clobberAttrs__");
nukeProp(el,"__doClobber__");
}
}
na=null;
};
};
if(dojo.render.html.ie){
dojo.addOnUnload(function(){
dojo._ie_clobber.clobber();
try{
if((dojo["widget"])&&(dojo.widget["manager"])){
dojo.widget.manager.destroyAll();
}
}
catch(e){
}
try{
window.onload=null;
}
catch(e){
}
try{
window.onunload=null;
}
catch(e){
}
dojo._ie_clobber.clobberNodes=[];
});
}
dojo.event.browser=new function(){
var _25f=0;
this.clean=function(node){
if(dojo.render.html.ie){
dojo._ie_clobber.clobber(node);
}
};
this.addClobberNode=function(node){
if(!dojo.render.html.ie){
return;
}
if(!node["__doClobber__"]){
node.__doClobber__=true;
dojo._ie_clobber.clobberNodes.push(node);
node.__clobberAttrs__=[];
}
};
this.addClobberNodeAttrs=function(node,_263){
if(!dojo.render.html.ie){
return;
}
this.addClobberNode(node);
for(var x=0;x<_263.length;x++){
node.__clobberAttrs__.push(_263[x]);
}
};
this.removeListener=function(node,_266,fp,_268){
if(!_268){
var _268=false;
}
_266=_266.toLowerCase();
if(_266.substr(0,2)=="on"){
_266=_266.substr(2);
}
if(node.removeEventListener){
node.removeEventListener(_266,fp,_268);
}
};
this.addListener=function(node,_26a,fp,_26c,_26d){
if(!node){
return;
}
if(!_26c){
var _26c=false;
}
_26a=_26a.toLowerCase();
if(_26a.substr(0,2)!="on"){
_26a="on"+_26a;
}
if(!_26d){
var _26e=function(evt){
if(!evt){
evt=window.event;
}
var ret=fp(dojo.event.browser.fixEvent(evt,this));
if(_26c){
dojo.event.browser.stopEvent(evt);
}
return ret;
};
}else{
_26e=fp;
}
if(node.addEventListener){
node.addEventListener(_26a.substr(2),_26e,_26c);
return _26e;
}else{
if(typeof node[_26a]=="function"){
var _271=node[_26a];
node[_26a]=function(e){
_271(e);
return _26e(e);
};
}else{
node[_26a]=_26e;
}
if(dojo.render.html.ie){
this.addClobberNodeAttrs(node,[_26a]);
}
return _26e;
}
};
this.isEvent=function(obj){
return (typeof obj!="undefined")&&(typeof Event!="undefined")&&(obj.eventPhase);
};
this.currentEvent=null;
this.callListener=function(_274,_275){
if(typeof _274!="function"){
dojo.raise("listener not a function: "+_274);
}
dojo.event.browser.currentEvent.currentTarget=_275;
return _274.call(_275,dojo.event.browser.currentEvent);
};
this.stopPropagation=function(){
dojo.event.browser.currentEvent.cancelBubble=true;
};
this.preventDefault=function(){
dojo.event.browser.currentEvent.returnValue=false;
};
this.keys={KEY_BACKSPACE:8,KEY_TAB:9,KEY_ENTER:13,KEY_SHIFT:16,KEY_CTRL:17,KEY_ALT:18,KEY_PAUSE:19,KEY_CAPS_LOCK:20,KEY_ESCAPE:27,KEY_SPACE:32,KEY_PAGE_UP:33,KEY_PAGE_DOWN:34,KEY_END:35,KEY_HOME:36,KEY_LEFT_ARROW:37,KEY_UP_ARROW:38,KEY_RIGHT_ARROW:39,KEY_DOWN_ARROW:40,KEY_INSERT:45,KEY_DELETE:46,KEY_LEFT_WINDOW:91,KEY_RIGHT_WINDOW:92,KEY_SELECT:93,KEY_F1:112,KEY_F2:113,KEY_F3:114,KEY_F4:115,KEY_F5:116,KEY_F6:117,KEY_F7:118,KEY_F8:119,KEY_F9:120,KEY_F10:121,KEY_F11:122,KEY_F12:123,KEY_NUM_LOCK:144,KEY_SCROLL_LOCK:145};
this.revKeys=[];
for(var key in this.keys){
this.revKeys[this.keys[key]]=key;
}
this.fixEvent=function(evt,_278){
if(!evt){
if(window["event"]){
evt=window.event;
}
}
if((evt["type"])&&(evt["type"].indexOf("key")==0)){
evt.keys=this.revKeys;
for(var key in this.keys){
evt[key]=this.keys[key];
}
if((dojo.render.html.ie)&&(evt["type"]=="keypress")){
evt.charCode=evt.keyCode;
}
}
if(dojo.render.html.ie){
if(!evt.target){
evt.target=evt.srcElement;
}
if(!evt.currentTarget){
evt.currentTarget=(_278?_278:evt.srcElement);
}
if(!evt.layerX){
evt.layerX=evt.offsetX;
}
if(!evt.layerY){
evt.layerY=evt.offsetY;
}
var doc=(evt.srcElement&&evt.srcElement.ownerDocument)?evt.srcElement.ownerDocument:document;
var _27b=((dojo.render.html.ie55)||(doc["compatMode"]=="BackCompat"))?doc.body:doc.documentElement;
if(!evt.pageX){
evt.pageX=evt.clientX+(_27b.scrollLeft||0);
}
if(!evt.pageY){
evt.pageY=evt.clientY+(_27b.scrollTop||0);
}
if(evt.type=="mouseover"){
evt.relatedTarget=evt.fromElement;
}
if(evt.type=="mouseout"){
evt.relatedTarget=evt.toElement;
}
this.currentEvent=evt;
evt.callListener=this.callListener;
evt.stopPropagation=this.stopPropagation;
evt.preventDefault=this.preventDefault;
}
return evt;
};
this.stopEvent=function(ev){
if(window.event){
ev.returnValue=false;
ev.cancelBubble=true;
}else{
ev.preventDefault();
ev.stopPropagation();
}
};
};
dojo.provide("dojo.event.*");
dojo.provide("dojo.widget.Manager");
dojo.widget.manager=new function(){
this.widgets=[];
this.widgetIds=[];
this.topWidgets={};
var _27d={};
var _27e=[];
this.getUniqueId=function(_27f){
return _27f+"_"+(_27d[_27f]!=undefined?++_27d[_27f]:_27d[_27f]=0);
};
this.add=function(_280){
this.widgets.push(_280);
if(!_280.extraArgs["id"]){
_280.extraArgs["id"]=_280.extraArgs["ID"];
}
if(_280.widgetId==""){
if(_280["id"]){
_280.widgetId=_280["id"];
}else{
if(_280.extraArgs["id"]){
_280.widgetId=_280.extraArgs["id"];
}else{
_280.widgetId=this.getUniqueId(_280.widgetType);
}
}
}
if(this.widgetIds[_280.widgetId]){
dojo.debug("widget ID collision on ID: "+_280.widgetId);
}
this.widgetIds[_280.widgetId]=_280;
};
this.destroyAll=function(){
for(var x=this.widgets.length-1;x>=0;x--){
try{
this.widgets[x].destroy(true);
delete this.widgets[x];
}
catch(e){
}
}
};
this.remove=function(_282){
if(dojo.lang.isNumber(_282)){
var tw=this.widgets[_282].widgetId;
delete this.widgetIds[tw];
this.widgets.splice(_282,1);
}else{
this.removeById(_282);
}
};
this.removeById=function(id){
if(!dojo.lang.isString(id)){
id=id["widgetId"];
if(!id){
dojo.debug("invalid widget or id passed to removeById");
return;
}
}
for(var i=0;i<this.widgets.length;i++){
if(this.widgets[i].widgetId==id){
this.remove(i);
break;
}
}
};
this.getWidgetById=function(id){
if(dojo.lang.isString(id)){
return this.widgetIds[id];
}
return id;
};
this.getWidgetsByType=function(type){
var lt=type.toLowerCase();
var ret=[];
dojo.lang.forEach(this.widgets,function(x){
if(x.widgetType.toLowerCase()==lt){
ret.push(x);
}
});
return ret;
};
this.getWidgetsByFilter=function(_28b,_28c){
var ret=[];
dojo.lang.every(this.widgets,function(x){
if(_28b(x)){
ret.push(x);
if(_28c){
return false;
}
}
return true;
});
return (_28c?ret[0]:ret);
};
this.getAllWidgets=function(){
return this.widgets.concat();
};
this.getWidgetByNode=function(node){
var w=this.getAllWidgets();
node=dojo.byId(node);
for(var i=0;i<w.length;i++){
if(w[i].domNode==node){
return w[i];
}
}
return null;
};
this.byId=this.getWidgetById;
this.byType=this.getWidgetsByType;
this.byFilter=this.getWidgetsByFilter;
this.byNode=this.getWidgetByNode;
var _292={};
var _293=["dojo.widget"];
for(var i=0;i<_293.length;i++){
_293[_293[i]]=true;
}
this.registerWidgetPackage=function(_295){
if(!_293[_295]){
_293[_295]=true;
_293.push(_295);
}
};
this.getWidgetPackageList=function(){
return dojo.lang.map(_293,function(elt){
return (elt!==true?elt:undefined);
});
};
this.getImplementation=function(_297,_298,_299,_29a){
var impl=this.getImplementationName(_297,_29a);
if(impl){
var ret;
if(_298){
ret=new impl(ctor);
}else{
ret=new impl();
}
return ret;
}
};
this.getImplementationName=function(_29d,_29e){
if(!_29e){
_29e="dojo";
}
var _29f=_29d.toLowerCase();
if(!_292[_29e]){
_292[_29e]={};
}
var impl=_292[_29e][_29f];
if(impl){
return impl;
}
var ns=dojo.getNamespace(_29e);
if(ns){
ns.load(_29d);
}
if(!_27e.length){
for(var _2a2 in dojo.render){
if(dojo.render[_2a2]["capable"]===true){
var _2a3=dojo.render[_2a2].prefixes;
for(var i=0;i<_2a3.length;i++){
_27e.push(_2a3[i].toLowerCase());
}
}
}
_27e.push("");
}
var _2a5=null;
var _2a6=false;
for(var _2a7=0;_2a7<2;_2a7++){
for(var i=0;i<_293.length;i++){
var _2a8=dojo.evalObjPath(_293[i]);
if(!_2a8){
continue;
}
var pos=_293[i].indexOf(".");
if(pos>-1){
var n=_293[i].substring(0,pos);
if(n!=_29e){
if(_2a7==0){
continue;
}
if(!_2a6){
_2a6=true;
dojo.deprecated("dojo.widget.Manager.getImplementationName","Wrong namespace ("+_29e+") specified. Developers should specify correct namespaces for all non-Dojo widgets","0.5");
}
}
}
for(var j=0;j<_27e.length;j++){
if(!_2a8[_27e[j]]){
continue;
}
for(var _2ac in _2a8[_27e[j]]){
if(_2ac.toLowerCase()!=_29f){
continue;
}
_292[_29e][_29f]=_2a8[_27e[j]][_2ac];
return _292[_29e][_29f];
}
}
for(var j=0;j<_27e.length;j++){
for(var _2ac in _2a8){
if(_2ac.toLowerCase()!=(_27e[j]+_29f)&&_2ac.toLowerCase()!=_29f){
continue;
}
_292[_29e][_29f]=_2a8[_2ac];
return _292[_29e][_29f];
}
}
}
var _2ad=dojo.findNamespaceForWidget(_29f);
if(_2ad){
_29e=_2ad.nsPrefix;
}
}
throw new Error("Could not locate \""+_29d+"\" class");
};
this.resizing=false;
this.onWindowResized=function(){
if(this.resizing){
return;
}
try{
this.resizing=true;
for(var id in this.topWidgets){
var _2af=this.topWidgets[id];
if(_2af.checkSize){
_2af.checkSize();
}
}
}
catch(e){
}
finally{
this.resizing=false;
}
};
if(typeof window!="undefined"){
dojo.addOnLoad(this,"onWindowResized");
dojo.event.connect(window,"onresize",this,"onWindowResized");
}
};
(function(){
var dw=dojo.widget;
var dwm=dw.manager;
var h=dojo.lang.curry(dojo.lang,"hitch",dwm);
var g=function(_2b4,_2b5){
dw[(_2b5||_2b4)]=h(_2b4);
};
g("add","addWidget");
g("destroyAll","destroyAllWidgets");
g("remove","removeWidget");
g("removeById","removeWidgetById");
g("getWidgetById");
g("getWidgetById","byId");
g("getWidgetsByType");
g("getWidgetsByFilter");
g("getWidgetsByType","byType");
g("getWidgetsByFilter","byFilter");
g("getWidgetByNode","byNode");
dw.all=function(n){
var _2b7=dwm.getAllWidgets.apply(dwm,arguments);
if(arguments.length>0){
return _2b7[n];
}
return _2b7;
};
g("registerWidgetPackage");
g("getImplementation","getWidgetImplementation");
g("getImplementationName","getWidgetImplementationName");
dw.widgets=dwm.widgets;
dw.widgetIds=dwm.widgetIds;
dw.root=dwm.root;
})();
dojo.provide("dojo.widget.Widget");
dojo.provide("dojo.widget.tags");
dojo.declare("dojo.widget.Widget",null,{initializer:function(){
this.children=[];
this.extraArgs={};
},parent:null,isTopLevel:false,isModal:false,isEnabled:true,isHidden:false,isContainer:false,widgetId:"",widgetType:"Widget",namespace:"dojo",toString:function(){
return "[Widget "+this.widgetType+", "+(this.widgetId||"NO ID")+"]";
},repr:function(){
return this.toString();
},enable:function(){
this.isEnabled=true;
},disable:function(){
this.isEnabled=false;
},hide:function(){
this.isHidden=true;
},show:function(){
this.isHidden=false;
},onResized:function(){
this.notifyChildrenOfResize();
},notifyChildrenOfResize:function(){
for(var i=0;i<this.children.length;i++){
var _2b9=this.children[i];
if(_2b9.onResized){
_2b9.onResized();
}
}
},create:function(args,_2bb,_2bc,_2bd){
if(_2bd){
this.namespace=_2bd;
}
this.satisfyPropertySets(args,_2bb,_2bc);
this.mixInProperties(args,_2bb,_2bc);
this.postMixInProperties(args,_2bb,_2bc);
dojo.widget.manager.add(this);
this.buildRendering(args,_2bb,_2bc);
this.initialize(args,_2bb,_2bc);
this.postInitialize(args,_2bb,_2bc);
this.postCreate(args,_2bb,_2bc);
return this;
},destroy:function(_2be){
this.destroyChildren();
this.uninitialize();
this.destroyRendering(_2be);
dojo.widget.manager.removeById(this.widgetId);
},destroyChildren:function(){
while(this.children.length>0){
var tc=this.children[0];
this.removeChild(tc);
tc.destroy();
}
},getChildrenOfType:function(type,_2c1){
var ret=[];
var _2c3=dojo.lang.isFunction(type);
if(!_2c3){
type=type.toLowerCase();
}
for(var x=0;x<this.children.length;x++){
if(_2c3){
if(this.children[x] instanceof type){
ret.push(this.children[x]);
}
}else{
if(this.children[x].widgetType.toLowerCase()==type){
ret.push(this.children[x]);
}
}
if(_2c1){
ret=ret.concat(this.children[x].getChildrenOfType(type,_2c1));
}
}
return ret;
},getDescendants:function(){
var _2c5=[];
var _2c6=[this];
var elem;
while((elem=_2c6.pop())){
_2c5.push(elem);
if(elem.children){
dojo.lang.forEach(elem.children,function(elem){
_2c6.push(elem);
});
}
}
return _2c5;
},isFirstNode:function(){
return this===this.parent.children[0];
},isLastNode:function(){
return this===this.parent.children[this.parent.children.length-1];
},satisfyPropertySets:function(args){
return args;
},mixInProperties:function(args,frag){
if((args["fastMixIn"])||(frag["fastMixIn"])){
for(var x in args){
this[x]=args[x];
}
return;
}
var _2cd;
var _2ce=dojo.widget.lcArgsCache[this.widgetType];
if(_2ce==null){
_2ce={};
for(var y in this){
_2ce[((new String(y)).toLowerCase())]=y;
}
dojo.widget.lcArgsCache[this.widgetType]=_2ce;
}
var _2d0={};
for(var x in args){
if(!this[x]){
var y=_2ce[(new String(x)).toLowerCase()];
if(y){
args[y]=args[x];
x=y;
}
}
if(_2d0[x]){
continue;
}
_2d0[x]=true;
if((typeof this[x])!=(typeof _2cd)){
if(typeof args[x]!="string"){
this[x]=args[x];
}else{
if(dojo.lang.isString(this[x])){
this[x]=args[x];
}else{
if(dojo.lang.isNumber(this[x])){
this[x]=new Number(args[x]);
}else{
if(dojo.lang.isBoolean(this[x])){
this[x]=(args[x].toLowerCase()=="false")?false:true;
}else{
if(dojo.lang.isFunction(this[x])){
if(args[x].search(/[^\w\.]+/i)==-1){
this[x]=dojo.evalObjPath(args[x],false);
}else{
var tn=dojo.lang.nameAnonFunc(new Function(args[x]),this);
dojo.event.connect(this,x,this,tn);
}
}else{
if(dojo.lang.isArray(this[x])){
this[x]=args[x].split(";");
}else{
if(this[x] instanceof Date){
this[x]=new Date(Number(args[x]));
}else{
if(typeof this[x]=="object"){
if(this[x] instanceof dojo.uri.Uri){
this[x]=args[x];
}else{
var _2d2=args[x].split(";");
for(var y=0;y<_2d2.length;y++){
var si=_2d2[y].indexOf(":");
if((si!=-1)&&(_2d2[y].length>si)){
this[x][_2d2[y].substr(0,si).replace(/^\s+|\s+$/g,"")]=_2d2[y].substr(si+1);
}
}
}
}else{
this[x]=args[x];
}
}
}
}
}
}
}
}
}else{
this.extraArgs[x.toLowerCase()]=args[x];
}
}
},postMixInProperties:function(){
},initialize:function(args,frag){
return false;
},postInitialize:function(args,frag){
return false;
},postCreate:function(args,frag){
return false;
},uninitialize:function(){
return false;
},buildRendering:function(){
dojo.unimplemented("dojo.widget.Widget.buildRendering, on "+this.toString()+", ");
return false;
},destroyRendering:function(){
dojo.unimplemented("dojo.widget.Widget.destroyRendering");
return false;
},cleanUp:function(){
dojo.unimplemented("dojo.widget.Widget.cleanUp");
return false;
},addedTo:function(_2da){
},addChild:function(_2db){
dojo.unimplemented("dojo.widget.Widget.addChild");
return false;
},removeChild:function(_2dc){
for(var x=0;x<this.children.length;x++){
if(this.children[x]===_2dc){
this.children.splice(x,1);
break;
}
}
return _2dc;
},resize:function(_2de,_2df){
this.setWidth(_2de);
this.setHeight(_2df);
},setWidth:function(_2e0){
if((typeof _2e0=="string")&&(_2e0.substr(-1)=="%")){
this.setPercentageWidth(_2e0);
}else{
this.setNativeWidth(_2e0);
}
},setHeight:function(_2e1){
if((typeof _2e1=="string")&&(_2e1.substr(-1)=="%")){
this.setPercentageHeight(_2e1);
}else{
this.setNativeHeight(_2e1);
}
},setPercentageHeight:function(_2e2){
return false;
},setNativeHeight:function(_2e3){
return false;
},setPercentageWidth:function(_2e4){
return false;
},setNativeWidth:function(_2e5){
return false;
},getPreviousSibling:function(){
var idx=this.getParentIndex();
if(idx<=0){
return null;
}
return this.getSiblings()[idx-1];
},getSiblings:function(){
return this.parent.children;
},getParentIndex:function(){
return dojo.lang.indexOf(this.getSiblings(),this,true);
},getNextSibling:function(){
var idx=this.getParentIndex();
if(idx==this.getSiblings().length-1){
return null;
}
if(idx<0){
return null;
}
return this.getSiblings()[idx+1];
}});
dojo.widget.lcArgsCache={};
dojo.widget.tags={};
dojo.widget.tags.addParseTreeHandler=function(type){
var _2e9=type.toLowerCase();
this[_2e9]=function(_2ea,_2eb,_2ec,_2ed,_2ee){
var _2ef=_2e9;
dojo.profile.start(_2ef);
var n=dojo.widget.buildWidgetFromParseTree(_2e9,_2ea,_2eb,_2ec,_2ed,_2ee);
dojo.profile.end(_2ef);
return n;
};
};
dojo.widget.tags.addParseTreeHandler("dojo:widget");
dojo.widget.tags["dojo:propertyset"]=function(_2f1,_2f2,_2f3){
var _2f4=_2f2.parseProperties(_2f1["dojo:propertyset"]);
};
dojo.widget.tags["dojo:connect"]=function(_2f5,_2f6,_2f7){
var _2f8=_2f6.parseProperties(_2f5["dojo:connect"]);
};
dojo.widget.buildWidgetFromParseTree=function(type,frag,_2fb,_2fc,_2fd,_2fe){
var _2ff=type.split(":");
_2ff=(_2ff.length==2)?_2ff[1]:type;
var _300=_2fe||_2fb.parseProperties(frag[frag.namespace+":"+_2ff]);
var _301=dojo.widget.manager.getImplementation(_2ff,null,null,frag.namespace);
if(!_301){
throw new Error("cannot find \""+_2ff+"\" widget");
}else{
if(!_301.create){
throw new Error("\""+_2ff+"\" widget object does not appear to implement *Widget");
}
}
_300["dojoinsertionindex"]=_2fd;
var ret=_301.create(_300,frag,_2fc,frag.namespace);
return ret;
};
dojo.widget.defineWidget=function(_303,_304,_305,init,_307){
if(dojo.lang.isString(arguments[3])){
dojo.widget._defineWidget(arguments[0],arguments[3],arguments[1],arguments[4],arguments[2]);
}else{
var args=[arguments[0]],p=3;
if(dojo.lang.isString(arguments[1])){
args.push(arguments[1],arguments[2]);
}else{
args.push("",arguments[1]);
p=2;
}
if(dojo.lang.isFunction(arguments[p])){
args.push(arguments[p],arguments[p+1]);
}else{
args.push(null,arguments[p]);
}
dojo.widget._defineWidget.apply(this,args);
}
};
dojo.widget.defineWidget.renderers="html|svg|vml";
dojo.widget._defineWidget=function(_309,_30a,_30b,init,_30d){
var _30e=_309.split(".");
var type=_30e.pop();
var regx="\\.("+(_30a?_30a+"|":"")+dojo.widget.defineWidget.renderers+")\\.";
var r=_309.search(new RegExp(regx));
_30e=(r<0?_30e.join("."):_309.substr(0,r));
dojo.widget.manager.registerWidgetPackage(_30e);
var pos=_30e.indexOf(".");
var _313=(pos>-1)?_30e.substring(0,pos):_30e;
dojo.widget.tags.addParseTreeHandler(_313+":"+type.toLowerCase());
if(_313!="dojo"){
dojo.widget.tags.addParseTreeHandler("dojo:"+type.toLowerCase());
}
_30d=(_30d)||{};
_30d.widgetType=type;
if((!init)&&(_30d["classConstructor"])){
init=_30d.classConstructor;
delete _30d.classConstructor;
}
dojo.declare(_309,_30b,init,_30d);
};
dojo.provide("dojo.namespace");
dojo.Namespace=function(_314,_315,_316,_317){
this.root=_314;
this.location=_315;
this.nsPrefix=_316;
this.resolver=_317;
dojo.setModulePrefix(_316,_315);
};
dojo.Namespace.prototype._loaded={};
dojo.Namespace.prototype.load=function(name,_319){
if(this.resolver){
var _31a=this.resolver(name,_319);
if(_31a&&!this._loaded[_31a]){
var req=dojo.require;
req(_31a);
this._loaded[_31a]=true;
}
if(this._loaded[_31a]){
return true;
}
}
return false;
};
dojo.defineNamespace=function(_31c,_31d,_31e,_31f,_320){
if(dojo._namespaces[_31c]){
return;
}
var ns=new dojo.Namespace(_31c,_31d,_31e,_31f);
dojo._namespaces[_31c]=ns;
if(_31e){
dojo._namespaces[_31e]=ns;
}
if(_320){
dojo.widget.manager.registerWidgetPackage(_320);
}
};
dojo.findNamespaceForWidget=function(_322){
dojo.deprecated("dojo.findNamespaceForWidget","Widget not defined for a namespace"+", so searching all namespaces. Developers should specify namespaces for all non-Dojo widgets","0.5");
_322=_322.toLowerCase();
for(x in dojo._namespaces){
if(dojo._namespaces[x].load(_322)){
return dojo._namespaces[x];
}
}
};
dojo.provide("dojo.widget.Parse");
dojo.widget.Parse=function(_323){
this.propertySetsList=[];
this.fragment=_323;
this.createComponents=function(frag,_325){
var _326=[];
var _327=false;
try{
if((frag)&&(frag["tagName"])&&(frag!=frag["nodeRef"])){
var _328=dojo.widget.tags;
var tna=String(frag["tagName"]).split(";");
for(var x=0;x<tna.length;x++){
var ltn=(tna[x].replace(/^\s+|\s+$/g,"")).toLowerCase();
var pos=ltn.indexOf(":");
var _32d=(pos>0)?ltn.substring(0,pos):null;
if(!_328[ltn]&&dojo.getNamespace&&dojo.lang.isString(ltn)&&pos>0){
var ns=dojo.getNamespace(_32d);
var _32f=ltn.substring(pos+1,ltn.length);
var _330=null;
var _331=frag[ltn]["dojoDomain"]||frag[ltn]["dojodomain"];
if(_331){
_330=_331[0].value;
}
if(ns){
ns.load(_32f,_330);
}
}
if(!_328[ltn]){
dojo.deprecated("dojo.widget.Parse.createComponents","Widget not defined for  namespace"+_32d+", so searching all namespaces. Developers should specify namespaces for all non-Dojo widgets","0.5");
var _332=dojo.findNamespaceForWidget(_32f);
if(_332){
ltn=_332.nsPrefix+":"+(ltn.indexOf(":")>0?ltn.substring(ltn.indexOf(":")+1):ltn);
}
}
if(_328[ltn]){
_327=true;
frag.tagName=ltn;
var ret=_328[ltn](frag,this,_325,frag["index"]);
_326.push(ret);
}else{
if(dojo.lang.isString(ltn)&&_32d&&dojo._namespaces[_32d]){
dojo.debug("no tag handler registered for type: ",ltn);
}
}
}
}
}
catch(e){
dojo.debug("dojo.widget.Parse: error:",e);
}
if(!_327){
_326=_326.concat(this.createSubComponents(frag,_325));
}
return _326;
};
this.createSubComponents=function(_334,_335){
var frag,comps=[];
for(var item in _334){
frag=_334[item];
if((frag)&&(typeof frag=="object")&&(frag!=_334.nodeRef)&&(frag!=_334["tagName"])){
comps=comps.concat(this.createComponents(frag,_335));
}
}
return comps;
};
this.parsePropertySets=function(_338){
return [];
var _339=[];
for(var item in _338){
if((_338[item]["tagName"]=="dojo:propertyset")){
_339.push(_338[item]);
}
}
this.propertySetsList.push(_339);
return _339;
};
this.parseProperties=function(_33b){
var _33c={};
for(var item in _33b){
if((_33b[item]==_33b["tagName"])||(_33b[item]==_33b.nodeRef)){
}else{
if((_33b[item]["tagName"])&&(dojo.widget.tags[_33b[item].tagName.toLowerCase()])){
}else{
if((_33b[item][0])&&(_33b[item][0].value!="")&&(_33b[item][0].value!=null)){
try{
if(item.toLowerCase()=="dataprovider"){
var _33e=this;
this.getDataProvider(_33e,_33b[item][0].value);
_33c.dataProvider=this.dataProvider;
}
_33c[item]=_33b[item][0].value;
var _33f=this.parseProperties(_33b[item]);
for(var _340 in _33f){
_33c[_340]=_33f[_340];
}
}
catch(e){
dojo.debug(e);
}
}
}
}
}
return _33c;
};
this.getDataProvider=function(_341,_342){
dojo.io.bind({url:_342,load:function(type,_344){
if(type=="load"){
_341.dataProvider=_344;
}
},mimetype:"text/javascript",sync:true});
};
this.getPropertySetById=function(_345){
for(var x=0;x<this.propertySetsList.length;x++){
if(_345==this.propertySetsList[x]["id"][0].value){
return this.propertySetsList[x];
}
}
return "";
};
this.getPropertySetsByType=function(_347){
var _348=[];
for(var x=0;x<this.propertySetsList.length;x++){
var cpl=this.propertySetsList[x];
var cpcc=cpl["componentClass"]||cpl["componentType"]||null;
var _34c=this.propertySetsList[x]["id"][0].value;
if((cpcc)&&(_34c==cpcc[0].value)){
_348.push(cpl);
}
}
return _348;
};
this.getPropertySets=function(_34d){
var ppl="dojo:propertyproviderlist";
var _34f=[];
var _350=_34d["tagName"];
if(_34d[ppl]){
var _351=_34d[ppl].value.split(" ");
for(var _352 in _351){
if((_352.indexOf("..")==-1)&&(_352.indexOf("://")==-1)){
var _353=this.getPropertySetById(_352);
if(_353!=""){
_34f.push(_353);
}
}else{
}
}
}
return (this.getPropertySetsByType(_350)).concat(_34f);
};
this.createComponentFromScript=function(_354,_355,_356,_357){
if(!_357){
_357="dojo";
}
var ltn=_357+":"+_355.toLowerCase();
var _359=dojo.widget.tags;
if(!_359[ltn]&&dojo.getNamespace&&dojo.lang.isString(ltn)){
var ns=dojo.getNamespace(_357);
if(ns){
ns.load(_355);
}
}
if(!_359[ltn]){
dojo.deprecated("dojo.widget.Parse.createComponentFromScript","Widget not defined for namespace"+_357+", so searching all namespaces. Developers should specify namespaces for all non-Dojo widgets","0.5");
var _35b=dojo.findNamespaceForWidget(_355.toLowerCase());
if(_35b){
var _35c=_35b.nsPrefix+":"+(ltn.indexOf(":")>0?ltn.substring(ltn.indexOf(":")+1):ltn);
_356[_35c]=_356[ltn];
_356.namespace=_35b.nsPrefix;
ltn=_35c;
}
}
if(_359[ltn]){
_356.fastMixIn=true;
var ret=[dojo.widget.buildWidgetFromParseTree(ltn,_356,this,null,null,_356)];
return ret;
}else{
dojo.debug("no tag handler registered for type: ",ltn);
}
};
};
dojo.widget._parser_collection={"dojo":new dojo.widget.Parse()};
dojo.widget.getParser=function(name){
if(!name){
name="dojo";
}
if(!this._parser_collection[name]){
this._parser_collection[name]=new dojo.widget.Parse();
}
return this._parser_collection[name];
};
dojo.widget.createWidget=function(name,_360,_361,_362){
var _363=false;
var _364=(typeof name=="string");
if(_364){
var pos=name.indexOf(":");
var _366=(pos>-1)?name.substring(0,pos):"dojo";
if(pos>-1){
name=name.substring(pos+1);
}
var _367=name.toLowerCase();
var _368=_366+":"+_367;
_363=(dojo.byId(name)&&(!dojo.widget.tags[_368]));
}
if((arguments.length==1)&&((_363)||(!_364))){
var xp=new dojo.xml.Parse();
var tn=(_363)?dojo.byId(name):name;
return dojo.widget.getParser().createComponents(xp.parseElement(tn,null,true))[0];
}
function fromScript(_36b,name,_36d,_36e){
_36d[_368]={dojotype:[{value:_367}],nodeRef:_36b,fastMixIn:true};
_36d.namespace=_36e;
return dojo.widget.getParser().createComponentFromScript(_36b,name,_36d,_36e);
}
_360=_360||{};
var _36f=false;
var tn=null;
var h=dojo.render.html.capable;
if(h){
tn=document.createElement("span");
}
if(!_361){
_36f=true;
_361=tn;
if(h){
dojo.body().appendChild(_361);
}
}else{
if(_362){
dojo.dom.insertAtPosition(tn,_361,_362);
}else{
tn=_361;
}
}
var _371=fromScript(tn,name.toLowerCase(),_360,_366);
if(!_371||!_371[0]||typeof _371[0].widgetType=="undefined"){
throw new Error("createWidget: Creation of \""+name+"\" widget failed.");
}
if(_36f){
if(_371[0].domNode.parentNode){
_371[0].domNode.parentNode.removeChild(_371[0].domNode);
}
}
return _371[0];
};
dojo.provide("dojo.namespaces.dojo");
(function(){
var map={html:{"accordioncontainer":"dojo.widget.AccordionContainer","treerpccontroller":"dojo.widget.TreeRPCController","accordionpane":"dojo.widget.AccordionPane","button":"dojo.widget.Button","chart":"dojo.widget.Chart","checkbox":"dojo.widget.Checkbox","civicrmdatepicker":"dojo.widget.CiviCrmDatePicker","colorpalette":"dojo.widget.ColorPalette","combobox":"dojo.widget.ComboBox","contentpane":"dojo.widget.ContentPane","contextmenu":"dojo.widget.ContextMenu","datepicker":"dojo.widget.DatePicker","debugconsole":"dojo.widget.DebugConsole","dialog":"dojo.widget.Dialog","docpane":"dojo.widget.DocPane","dropdownbutton":"dojo.widget.DropdownButton","dropdowndatepicker":"dojo.widget.DropdownDatePicker","editor2":"dojo.widget.Editor2","editor2toolbar":"dojo.widget.Editor2Toolbar","editor":"dojo.widget.Editor","editortree":"dojo.widget.EditorTree","editortreecontextmenu":"dojo.widget.EditorTreeContextMenu","editortreenode":"dojo.widget.EditorTreeNode","fisheyelist":"dojo.widget.FisheyeList","editortreecontroller":"dojo.widget.EditorTreeController","googlemap":"dojo.widget.GoogleMap","editortreeselector":"dojo.widget.EditorTreeSelector","floatingpane":"dojo.widget.FloatingPane","hslcolorpicker":"dojo.widget.HslColorPicker","inlineeditbox":"dojo.widget.InlineEditBox","layoutcontainer":"dojo.widget.LayoutContainer","linkpane":"dojo.widget.LinkPane","manager":"dojo.widget.Manager","popupcontainer":"dojo.widget.Menu2","popupmenu2":"dojo.widget.Menu2","menuitem2":"dojo.widget.Menu2","menuseparator2":"dojo.widget.Menu2","menubar2":"dojo.widget.Menu2","menubaritem2":"dojo.widget.Menu2","monthlyCalendar":"dojo.widget.MonthlyCalendar","popupbutton":"dojo.widget.PopUpButton","richtext":"dojo.widget.RichText","remotetabcontroller":"dojo.widget.RemoteTabController","resizehandle":"dojo.widget.ResizeHandle","resizabletextarea":"dojo.widget.ResizableTextarea","slideshow":"dojo.widget.SlideShow","sortabletable":"dojo.widget.SortableTable","simpledropdownbuttons":"dojo.widget.SimpleDropdownButtons","splitcontainer":"dojo.widget.SplitContainer","svgbutton":"dojo.widget.SvgButton","tabcontainer":"dojo.widget.TabContainer","taskbar":"dojo.widget.TaskBar","timepicker":"dojo.widget.TimePicker","titlepane":"dojo.widget.TitlePane","toggler":"dojo.widget.Toggler","toolbar":"dojo.widget.Toolbar","tooltip":"dojo.widget.Tooltip","tree":"dojo.widget.Tree","treebasiccontroller":"dojo.widget.TreeBasicController","treecontextmenu":"dojo.widget.TreeContextMenu","treeselector":"dojo.widget.TreeSelector","treecontrollerextension":"dojo.widget.TreeControllerExtension","treenode":"dojo.widget.TreeNode","validate":"dojo.widget.validate","treeloadingcontroller":"dojo.widget.TreeLoadingController","widget":"dojo.widget.Widget","wizard":"dojo.widget.Wizard","yahoomap":"dojo.widget.YahooMap"},svg:{"chart":"dojo.widget.svg.Chart","hslcolorpicker":"dojo.widget.svg.HslColorPicker"},vml:{"chart":"dojo.widget.vml.Chart"}};
function dojoNamespaceResolver(name,_374){
if(!_374){
_374="html";
}
if(!map[_374]){
return null;
}
return map[_374][name];
}
dojo.defineNamespace("dojo","src","dojo",dojoNamespaceResolver);
dojo.addDojoNamespaceMapping=function(_375,_376){
map[_375]=_376;
};
})();
dojo.provide("dojo.html.style");
dojo.html.getClass=function(node){
node=dojo.byId(node);
if(!node){
return "";
}
var cs="";
if(node.className){
cs=node.className;
}else{
if(dojo.html.hasAttribute(node,"class")){
cs=dojo.html.getAttribute(node,"class");
}
}
return cs.replace(/^\s+|\s+$/g,"");
};
dojo.html.getClasses=function(node){
var c=dojo.html.getClass(node);
return (c=="")?[]:c.split(/\s+/g);
};
dojo.html.hasClass=function(node,_37c){
return (new RegExp("(^|\\s+)"+_37c+"(\\s+|$)")).test(dojo.html.getClass(node));
};
dojo.html.prependClass=function(node,_37e){
_37e+=" "+dojo.html.getClass(node);
return dojo.html.setClass(node,_37e);
};
dojo.html.addClass=function(node,_380){
if(dojo.html.hasClass(node,_380)){
return false;
}
_380=(dojo.html.getClass(node)+" "+_380).replace(/^\s+|\s+$/g,"");
return dojo.html.setClass(node,_380);
};
dojo.html.setClass=function(node,_382){
node=dojo.byId(node);
var cs=new String(_382);
try{
if(typeof node.className=="string"){
node.className=cs;
}else{
if(node.setAttribute){
node.setAttribute("class",_382);
node.className=cs;
}else{
return false;
}
}
}
catch(e){
dojo.debug("dojo.html.setClass() failed",e);
}
return true;
};
dojo.html.removeClass=function(node,_385,_386){
try{
if(!_386){
var _387=dojo.html.getClass(node).replace(new RegExp("(^|\\s+)"+_385+"(\\s+|$)"),"$1$2");
}else{
var _387=dojo.html.getClass(node).replace(_385,"");
}
dojo.html.setClass(node,_387);
}
catch(e){
dojo.debug("dojo.html.removeClass() failed",e);
}
return true;
};
dojo.html.replaceClass=function(node,_389,_38a){
dojo.html.removeClass(node,_38a);
dojo.html.addClass(node,_389);
};
dojo.html.classMatchType={ContainsAll:0,ContainsAny:1,IsOnly:2};
dojo.html.getElementsByClass=function(_38b,_38c,_38d,_38e,_38f){
var _390=dojo.doc();
_38c=dojo.byId(_38c)||_390;
var _391=_38b.split(/\s+/g);
var _392=[];
if(_38e!=1&&_38e!=2){
_38e=0;
}
var _393=new RegExp("(\\s|^)(("+_391.join(")|(")+"))(\\s|$)");
var _394=_391.join(" ").length;
var _395=[];
if(!_38f&&_390.evaluate){
var _396=".//"+(_38d||"*")+"[contains(";
if(_38e!=dojo.html.classMatchType.ContainsAny){
_396+="concat(' ',@class,' '), ' "+_391.join(" ') and contains(concat(' ',@class,' '), ' ")+" ')";
if(_38e==2){
_396+=" and string-length(@class)="+_394+"]";
}else{
_396+="]";
}
}else{
_396+="concat(' ',@class,' '), ' "+_391.join(" ')) or contains(concat(' ',@class,' '), ' ")+" ')]";
}
var _397=_390.evaluate(_396,_38c,null,XPathResult.ANY_TYPE,null);
var _398=_397.iterateNext();
while(_398){
try{
_395.push(_398);
_398=_397.iterateNext();
}
catch(e){
break;
}
}
return _395;
}else{
if(!_38d){
_38d="*";
}
_395=_38c.getElementsByTagName(_38d);
var node,i=0;
outer:
while(node=_395[i++]){
var _39a=dojo.html.getClasses(node);
if(_39a.length==0){
continue outer;
}
var _39b=0;
for(var j=0;j<_39a.length;j++){
if(_393.test(_39a[j])){
if(_38e==dojo.html.classMatchType.ContainsAny){
_392.push(node);
continue outer;
}else{
_39b++;
}
}else{
if(_38e==dojo.html.classMatchType.IsOnly){
continue outer;
}
}
}
if(_39b==_391.length){
if((_38e==dojo.html.classMatchType.IsOnly)&&(_39b==_39a.length)){
_392.push(node);
}else{
if(_38e==dojo.html.classMatchType.ContainsAll){
_392.push(node);
}
}
}
}
return _392;
}
};
dojo.html.getElementsByClassName=dojo.html.getElementsByClass;
dojo.html.toCamelCase=function(_39d){
var arr=_39d.split("-"),cc=arr[0];
for(var i=1;i<arr.length;i++){
cc+=arr[i].charAt(0).toUpperCase()+arr[i].substring(1);
}
return cc;
};
dojo.html.toSelectorCase=function(_3a0){
return _3a0.replace(/([A-Z])/g,"-$1").toLowerCase();
};
dojo.html.getComputedStyle=function(node,_3a2,_3a3){
node=dojo.byId(node);
var _3a2=dojo.html.toSelectorCase(_3a2);
var _3a4=dojo.html.toCamelCase(_3a2);
if(!node||!node.style){
return _3a3;
}else{
if(document.defaultView&&dojo.dom.isDescendantOf(node,node.ownerDocument)){
try{
var cs=document.defaultView.getComputedStyle(node,"");
if(cs){
return cs.getPropertyValue(_3a2);
}
}
catch(e){
if(node.style.getPropertyValue){
return node.style.getPropertyValue(_3a2);
}else{
return _3a3;
}
}
}else{
if(node.currentStyle){
return node.currentStyle[_3a4];
}
}
}
if(node.style.getPropertyValue){
return node.style.getPropertyValue(_3a2);
}else{
return _3a3;
}
};
dojo.html.getStyleProperty=function(node,_3a7){
node=dojo.byId(node);
return (node&&node.style?node.style[dojo.html.toCamelCase(_3a7)]:undefined);
};
dojo.html.getStyle=function(node,_3a9){
var _3aa=dojo.html.getStyleProperty(node,_3a9);
return (_3aa?_3aa:dojo.html.getComputedStyle(node,_3a9));
};
dojo.html.setStyle=function(node,_3ac,_3ad){
node=dojo.byId(node);
if(node&&node.style){
var _3ae=dojo.html.toCamelCase(_3ac);
node.style[_3ae]=_3ad;
}
};
dojo.html.copyStyle=function(_3af,_3b0){
if(!_3b0.style.cssText){
_3af.setAttribute("style",_3b0.getAttribute("style"));
}else{
_3af.style.cssText=_3b0.style.cssText;
}
dojo.html.addClass(_3af,dojo.html.getClass(_3b0));
};
dojo.html.getUnitValue=function(node,_3b2,_3b3){
var s=dojo.html.getComputedStyle(node,_3b2);
if((!s)||((s=="auto")&&(_3b3))){
return {value:0,units:"px"};
}
var _3b5=s.match(/(\-?[\d.]+)([a-z%]*)/i);
if(!_3b5){
return dojo.html.getUnitValue.bad;
}
return {value:Number(_3b5[1]),units:_3b5[2].toLowerCase()};
};
dojo.html.getUnitValue.bad={value:NaN,units:""};
dojo.html.getPixelValue=function(node,_3b7,_3b8){
var _3b9=dojo.html.getUnitValue(node,_3b7,_3b8);
if(isNaN(_3b9.value)){
return 0;
}
if((_3b9.value)&&(_3b9.units!="px")){
return NaN;
}
return _3b9.value;
};
dojo.html.setPositivePixelValue=function(node,_3bb,_3bc){
if(isNaN(_3bc)){
return false;
}
node.style[_3bb]=Math.max(0,_3bc)+"px";
return true;
};
dojo.html.styleSheet=null;
dojo.html.insertCssRule=function(_3bd,_3be,_3bf){
if(!dojo.html.styleSheet){
if(document.createStyleSheet){
dojo.html.styleSheet=document.createStyleSheet();
}else{
if(document.styleSheets[0]){
dojo.html.styleSheet=document.styleSheets[0];
}else{
return null;
}
}
}
if(arguments.length<3){
if(dojo.html.styleSheet.cssRules){
_3bf=dojo.html.styleSheet.cssRules.length;
}else{
if(dojo.html.styleSheet.rules){
_3bf=dojo.html.styleSheet.rules.length;
}else{
return null;
}
}
}
if(dojo.html.styleSheet.insertRule){
var rule=_3bd+" { "+_3be+" }";
return dojo.html.styleSheet.insertRule(rule,_3bf);
}else{
if(dojo.html.styleSheet.addRule){
return dojo.html.styleSheet.addRule(_3bd,_3be,_3bf);
}else{
return null;
}
}
};
dojo.html.removeCssRule=function(_3c1){
if(!dojo.html.styleSheet){
dojo.debug("no stylesheet defined for removing rules");
return false;
}
if(dojo.html.render.ie){
if(!_3c1){
_3c1=dojo.html.styleSheet.rules.length;
dojo.html.styleSheet.removeRule(_3c1);
}
}else{
if(document.styleSheets[0]){
if(!_3c1){
_3c1=dojo.html.styleSheet.cssRules.length;
}
dojo.html.styleSheet.deleteRule(_3c1);
}
}
return true;
};
dojo.html._insertedCssFiles=[];
dojo.html.insertCssFile=function(URI,doc,_3c4){
if(!URI){
return;
}
if(!doc){
doc=document;
}
var _3c5=dojo.hostenv.getText(URI);
_3c5=dojo.html.fixPathsInCssText(_3c5,URI);
if(_3c4){
var idx=-1,node,ent=dojo.html._insertedCssFiles;
for(var i=0;i<ent.length;i++){
if((ent[i].doc==doc)&&(ent[i].cssText==_3c5)){
idx=i;
node=ent[i].nodeRef;
break;
}
}
if(node){
var _3c8=doc.getElementsByTagName("style");
for(var i=0;i<_3c8.length;i++){
if(_3c8[i]==node){
return;
}
}
dojo.html._insertedCssFiles.shift(idx,1);
}
}
var _3c9=dojo.html.insertCssText(_3c5);
dojo.html._insertedCssFiles.push({"doc":doc,"cssText":_3c5,"nodeRef":_3c9});
if(_3c9&&djConfig.isDebug){
_3c9.setAttribute("dbgHref",URI);
}
return _3c9;
};
dojo.html.insertCssText=function(_3ca,doc,URI){
if(!_3ca){
return;
}
if(!doc){
doc=document;
}
if(URI){
_3ca=dojo.html.fixPathsInCssText(_3ca,URI);
}
var _3cd=doc.createElement("style");
_3cd.setAttribute("type","text/css");
var head=doc.getElementsByTagName("head")[0];
if(!head){
dojo.debug("No head tag in document, aborting styles");
return;
}else{
head.appendChild(_3cd);
}
if(_3cd.styleSheet){
_3cd.styleSheet.cssText=_3ca;
}else{
var _3cf=doc.createTextNode(_3ca);
_3cd.appendChild(_3cf);
}
return _3cd;
};
dojo.html.fixPathsInCssText=function(_3d0,URI){
if(!_3d0||!URI){
return;
}
var _3d2,str="",url="";
var _3d3=/url\(\s*([\t\s\w()\/.\\'"-:#=&?]+)\s*\)/;
var _3d4=/(file|https?|ftps?):\/\//;
var _3d5=/^[\s]*(['"]?)([\w()\/.\\'"-:#=&?]*)\1[\s]*?$/;
while(_3d2=_3d3.exec(_3d0)){
url=_3d2[1].replace(_3d5,"$2");
if(!_3d4.exec(url)){
url=(new dojo.uri.Uri(URI,url).toString());
}
str+=_3d0.substring(0,_3d2.index)+"url("+url+")";
_3d0=_3d0.substr(_3d2.index+_3d2[0].length);
}
return str+_3d0;
};
dojo.html.setActiveStyleSheet=function(_3d6){
var i=0,a,els=dojo.doc().getElementsByTagName("link");
while(a=els[i++]){
if(a.getAttribute("rel").indexOf("style")!=-1&&a.getAttribute("title")){
a.disabled=true;
if(a.getAttribute("title")==_3d6){
a.disabled=false;
}
}
}
};
dojo.html.getActiveStyleSheet=function(){
var i=0,a,els=dojo.doc().getElementsByTagName("link");
while(a=els[i++]){
if(a.getAttribute("rel").indexOf("style")!=-1&&a.getAttribute("title")&&!a.disabled){
return a.getAttribute("title");
}
}
return null;
};
dojo.html.getPreferredStyleSheet=function(){
var i=0,a,els=dojo.doc().getElementsByTagName("link");
while(a=els[i++]){
if(a.getAttribute("rel").indexOf("style")!=-1&&a.getAttribute("rel").indexOf("alt")==-1&&a.getAttribute("title")){
return a.getAttribute("title");
}
}
return null;
};
dojo.provide("dojo.uri.Uri");
dojo.uri=new function(){
this.dojoUri=function(uri){
return new dojo.uri.Uri(dojo.hostenv.getBaseScriptUri(),uri);
};
this.nsUri=function(_3db,uri){
var ns=dojo.getNamespace(_3db);
if(!ns){
return null;
}
var loc=ns.location;
if(loc.lastIndexOf("/")!=loc.length-1){
loc+="/";
}
return new dojo.uri.Uri(dojo.hostenv.getBaseScriptUri()+loc,uri);
};
this.Uri=function(){
var uri=arguments[0];
for(var i=1;i<arguments.length;i++){
if(!arguments[i]){
continue;
}
var _3e1=new dojo.uri.Uri(arguments[i].toString());
var _3e2=new dojo.uri.Uri(uri.toString());
if(_3e1.path==""&&_3e1.scheme==null&&_3e1.authority==null&&_3e1.query==null){
if(_3e1.fragment!=null){
_3e2.fragment=_3e1.fragment;
}
_3e1=_3e2;
}else{
if(_3e1.scheme==null){
_3e1.scheme=_3e2.scheme;
if(_3e1.authority==null){
_3e1.authority=_3e2.authority;
if(_3e1.path.charAt(0)!="/"){
var path=_3e2.path.substring(0,_3e2.path.lastIndexOf("/")+1)+_3e1.path;
var segs=path.split("/");
for(var j=0;j<segs.length;j++){
if(segs[j]=="."){
if(j==segs.length-1){
segs[j]="";
}else{
segs.splice(j,1);
j--;
}
}else{
if(j>0&&!(j==1&&segs[0]=="")&&segs[j]==".."&&segs[j-1]!=".."){
if(j==segs.length-1){
segs.splice(j,1);
segs[j-1]="";
}else{
segs.splice(j-1,2);
j-=2;
}
}
}
}
_3e1.path=segs.join("/");
}
}
}
}
uri="";
if(_3e1.scheme!=null){
uri+=_3e1.scheme+":";
}
if(_3e1.authority!=null){
uri+="//"+_3e1.authority;
}
uri+=_3e1.path;
if(_3e1.query!=null){
uri+="?"+_3e1.query;
}
if(_3e1.fragment!=null){
uri+="#"+_3e1.fragment;
}
}
this.uri=uri.toString();
var _3e6="^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?$";
var r=this.uri.match(new RegExp(_3e6));
this.scheme=r[2]||(r[1]?"":null);
this.authority=r[4]||(r[3]?"":null);
this.path=r[5];
this.query=r[7]||(r[6]?"":null);
this.fragment=r[9]||(r[8]?"":null);
if(this.authority!=null){
_3e6="^((([^:]+:)?([^@]+))@)?([^:]*)(:([0-9]+))?$";
r=this.authority.match(new RegExp(_3e6));
this.user=r[3]||null;
this.password=r[4]||null;
this.host=r[5];
this.port=r[7]||null;
}
this.toString=function(){
return this.uri;
};
};
};
dojo.provide("dojo.uri.*");
dojo.provide("dojo.widget.DomWidget");
dojo.widget._cssFiles={};
dojo.widget._cssStrings={};
dojo.widget._templateCache={};
dojo.widget.defaultStrings={dojoRoot:dojo.hostenv.getBaseScriptUri(),baseScriptUri:dojo.hostenv.getBaseScriptUri()};
dojo.widget.buildFromTemplate=function(){
dojo.lang.forward("fillFromTemplateCache");
};
dojo.widget.fillFromTemplateCache=function(obj,_3e9,_3ea,_3eb){
var _3ec=_3e9||obj.templatePath;
if(_3ec&&!(_3ec instanceof dojo.uri.Uri)){
_3ec=dojo.uri.dojoUri(_3ec);
dojo.deprecated("templatePath should be of type dojo.uri.Uri",null,"0.4");
}
var _3ed=dojo.widget._templateCache;
if(!obj["widgetType"]){
do{
var _3ee="__dummyTemplate__"+dojo.widget._templateCache.dummyCount++;
}while(_3ed[_3ee]);
obj.widgetType=_3ee;
}
var wt=obj.widgetType;
var ts=_3ed[wt];
if(!ts){
_3ed[wt]={"string":null,"node":null};
if(_3eb){
ts={};
}else{
ts=_3ed[wt];
}
}
if((!obj.templateString)&&(!_3eb)){
obj.templateString=_3ea||ts["string"];
}
if((!obj.templateNode)&&(!_3eb)){
obj.templateNode=ts["node"];
}
if((!obj.templateNode)&&(!obj.templateString)&&(_3ec)){
var _3f1=dojo.hostenv.getText(_3ec);
if(_3f1){
_3f1=_3f1.replace(/^\s*<\?xml(\s)+version=[\'\"](\d)*.(\d)*[\'\"](\s)*\?>/im,"");
var _3f2=_3f1.match(/<body[^>]*>\s*([\s\S]+)\s*<\/body>/im);
if(_3f2){
_3f1=_3f2[1];
}
}else{
_3f1="";
}
obj.templateString=_3f1;
if(!_3eb){
_3ed[wt]["string"]=_3f1;
}
}
if((!ts["string"])&&(!_3eb)){
ts.string=obj.templateString;
}
};
dojo.widget._templateCache.dummyCount=0;
dojo.widget.attachProperties=["dojoAttachPoint","id"];
dojo.widget.eventAttachProperty="dojoAttachEvent";
dojo.widget.onBuildProperty="dojoOnBuild";
dojo.widget.waiNames=["waiRole","waiState"];
dojo.widget.wai={waiRole:{name:"waiRole",namespace:"http://www.w3.org/TR/xhtml2",alias:"x2",prefix:"wairole:"},waiState:{name:"waiState",namespace:"http://www.w3.org/2005/07/aaa",alias:"aaa",prefix:""},setAttr:function(node,ns,attr,_3f6){
if(dojo.render.html.ie){
node.setAttribute(this[ns].alias+":"+attr,this[ns].prefix+_3f6);
}else{
node.setAttributeNS(this[ns].namespace,attr,this[ns].prefix+_3f6);
}
},getAttr:function(node,ns,attr){
if(dojo.render.html.ie){
return node.getAttribute(this[ns].alias+":"+attr);
}else{
return node.getAttributeNS(this[ns].namespace,attr);
}
}};
dojo.widget.attachTemplateNodes=function(_3fa,_3fb,_3fc){
var _3fd=dojo.dom.ELEMENT_NODE;
function trim(str){
return str.replace(/^\s+|\s+$/g,"");
}
if(!_3fa){
_3fa=_3fb.domNode;
}
if(_3fa.nodeType!=_3fd){
return;
}
var _3ff=_3fa.all||_3fa.getElementsByTagName("*");
var _400=_3fb;
for(var x=-1;x<_3ff.length;x++){
var _402=(x==-1)?_3fa:_3ff[x];
var _403=[];
for(var y=0;y<this.attachProperties.length;y++){
var _405=_402.getAttribute(this.attachProperties[y]);
if(_405){
_403=_405.split(";");
for(var z=0;z<_403.length;z++){
if(dojo.lang.isArray(_3fb[_403[z]])){
_3fb[_403[z]].push(_402);
}else{
_3fb[_403[z]]=_402;
}
}
break;
}
}
var _407=_402.getAttribute(this.templateProperty);
if(_407){
_3fb[_407]=_402;
}
dojo.lang.forEach(dojo.widget.waiNames,function(name){
var wai=dojo.widget.wai[name];
var val=_402.getAttribute(wai.name);
if(val){
if(val.indexOf("-")==-1){
dojo.widget.wai.setAttr(_402,wai.name,"role",val);
}else{
var _40b=val.split("-");
dojo.widget.wai.setAttr(_402,wai.name,_40b[0],_40b[1]);
}
}
},this);
var _40c=_402.getAttribute(this.eventAttachProperty);
if(_40c){
var evts=_40c.split(";");
for(var y=0;y<evts.length;y++){
if((!evts[y])||(!evts[y].length)){
continue;
}
var _40e=null;
var tevt=trim(evts[y]);
if(evts[y].indexOf(":")>=0){
var _410=tevt.split(":");
tevt=trim(_410[0]);
_40e=trim(_410[1]);
}
if(!_40e){
_40e=tevt;
}
var tf=function(){
var ntf=new String(_40e);
return function(evt){
if(_400[ntf]){
_400[ntf](dojo.event.browser.fixEvent(evt,this));
}
};
}();
dojo.event.browser.addListener(_402,tevt,tf,false,true);
}
}
for(var y=0;y<_3fc.length;y++){
var _414=_402.getAttribute(_3fc[y]);
if((_414)&&(_414.length)){
var _40e=null;
var _415=_3fc[y].substr(4);
_40e=trim(_414);
var _416=[_40e];
if(_40e.indexOf(";")>=0){
_416=dojo.lang.map(_40e.split(";"),trim);
}
for(var z=0;z<_416.length;z++){
if(!_416[z].length){
continue;
}
var tf=function(){
var ntf=new String(_416[z]);
return function(evt){
if(_400[ntf]){
_400[ntf](dojo.event.browser.fixEvent(evt,this));
}
};
}();
dojo.event.browser.addListener(_402,_415,tf,false,true);
}
}
}
var _419=_402.getAttribute(this.onBuildProperty);
if(_419){
eval("var node = baseNode; var widget = targetObj; "+_419);
}
}
};
dojo.widget.getDojoEventsFromStr=function(str){
var re=/(dojoOn([a-z]+)(\s?))=/gi;
var evts=str?str.match(re)||[]:[];
var ret=[];
var lem={};
for(var x=0;x<evts.length;x++){
if(evts[x].legth<1){
continue;
}
var cm=evts[x].replace(/\s/,"");
cm=(cm.slice(0,cm.length-1));
if(!lem[cm]){
lem[cm]=true;
ret.push(cm);
}
}
return ret;
};
dojo.declare("dojo.widget.DomWidget",dojo.widget.Widget,{initializer:function(){
if((arguments.length>0)&&(typeof arguments[0]=="object")){
this.create(arguments[0]);
}
},templateNode:null,templateString:null,templateCssString:null,preventClobber:false,domNode:null,containerNode:null,addChild:function(_421,_422,pos,ref,_425){
if(!this.isContainer){
dojo.debug("dojo.widget.DomWidget.addChild() attempted on non-container widget");
return null;
}else{
if(_425==undefined){
_425=this.children.length;
}
this.addWidgetAsDirectChild(_421,_422,pos,ref,_425);
this.registerChild(_421,_425);
}
return _421;
},addWidgetAsDirectChild:function(_426,_427,pos,ref,_42a){
if((!this.containerNode)&&(!_427)){
this.containerNode=this.domNode;
}
var cn=(_427)?_427:this.containerNode;
if(!pos){
pos="after";
}
if(!ref){
if(!cn){
cn=dojo.body();
}
ref=cn.lastChild;
}
if(!_42a){
_42a=0;
}
_426.domNode.setAttribute("dojoinsertionindex",_42a);
if(!ref){
cn.appendChild(_426.domNode);
}else{
if(pos=="insertAtIndex"){
dojo.dom.insertAtIndex(_426.domNode,ref.parentNode,_42a);
}else{
if((pos=="after")&&(ref===cn.lastChild)){
cn.appendChild(_426.domNode);
}else{
dojo.dom.insertAtPosition(_426.domNode,cn,pos);
}
}
}
},registerChild:function(_42c,_42d){
_42c.dojoInsertionIndex=_42d;
var idx=-1;
for(var i=0;i<this.children.length;i++){
if(this.children[i].dojoInsertionIndex<_42d){
idx=i;
}
}
this.children.splice(idx+1,0,_42c);
_42c.parent=this;
_42c.addedTo(this,idx+1);
delete dojo.widget.manager.topWidgets[_42c.widgetId];
},removeChild:function(_430){
dojo.dom.removeNode(_430.domNode);
return dojo.widget.DomWidget.superclass.removeChild.call(this,_430);
},getFragNodeRef:function(frag){
if(!frag||!frag[this.namespace+":"+this.widgetType.toLowerCase()]){
dojo.raise("Error: no frag for widget type "+this.widgetType+" with namespace "+this.namespace+", id "+this.widgetId+" (maybe a widget has set it's type incorrectly)");
}
return frag?frag[this.namespace+":"+this.widgetType.toLowerCase()]["nodeRef"]:null;
},postInitialize:function(args,frag,_434){
var _435=this.getFragNodeRef(frag);
if(_434&&(_434.snarfChildDomOutput||!_435)){
_434.addWidgetAsDirectChild(this,"","insertAtIndex","",args["dojoinsertionindex"],_435);
}else{
if(_435){
if(this.domNode&&(this.domNode!==_435)){
var _436=_435.parentNode.replaceChild(this.domNode,_435);
}
}
}
if(_434){
_434.registerChild(this,args.dojoinsertionindex);
}else{
dojo.widget.manager.topWidgets[this.widgetId]=this;
}
if(this.isContainer&&!frag["dojoDontFollow"]){
var _437=dojo.widget.getParser();
_437.createSubComponents(frag,this);
}
},buildRendering:function(args,frag){
var ts=dojo.widget._templateCache[this.widgetType];
if(args["templatecsspath"]){
args["templateCssPath"]=args["templatecsspath"];
}
var _43b=args["templateCssPath"]||this.templateCssPath;
if(_43b&&!(_43b instanceof dojo.uri.Uri)){
_43b=dojo.uri.dojoUri(_43b);
dojo.deprecated("templateCssPath should be of type dojo.uri.Uri",null,"0.4");
}
if(_43b&&!dojo.widget._cssFiles[_43b.toString()]){
if((!this.templateCssString)&&(_43b)){
this.templateCssString=dojo.hostenv.getText(_43b);
this.templateCssPath=null;
}
dojo.widget._cssFiles[_43b.toString()]=true;
}
if((this["templateCssString"])&&(!this.templateCssString["loaded"])){
dojo.html.insertCssText(this.templateCssString,null,_43b);
if(!this.templateCssString){
this.templateCssString="";
}
this.templateCssString.loaded=true;
}
if((!this.preventClobber)&&((this.templatePath)||(this.templateNode)||((this["templateString"])&&(this.templateString.length))||((typeof ts!="undefined")&&((ts["string"])||(ts["node"]))))){
this.buildFromTemplate(args,frag);
}else{
this.domNode=this.getFragNodeRef(frag);
}
this.fillInTemplate(args,frag);
},buildFromTemplate:function(args,frag){
var _43e=false;
if(args["templatepath"]){
_43e=true;
args["templatePath"]=args["templatepath"];
}
dojo.widget.fillFromTemplateCache(this,args["templatePath"],null,_43e);
var ts=dojo.widget._templateCache[this.widgetType];
if((ts)&&(!_43e)){
if(!this.templateString.length){
this.templateString=ts["string"];
}
if(!this.templateNode){
this.templateNode=ts["node"];
}
}
var _440=false;
var node=null;
var tstr=this.templateString;
if((!this.templateNode)&&(this.templateString)){
_440=this.templateString.match(/\$\{([^\}]+)\}/g);
if(_440){
var hash=this.strings||{};
for(var key in dojo.widget.defaultStrings){
if(dojo.lang.isUndefined(hash[key])){
hash[key]=dojo.widget.defaultStrings[key];
}
}
for(var i=0;i<_440.length;i++){
var key=_440[i];
key=key.substring(2,key.length-1);
var kval=(key.substring(0,5)=="this.")?dojo.lang.getObjPathValue(key.substring(5),this):hash[key];
var _447;
if((kval)||(dojo.lang.isString(kval))){
_447=(dojo.lang.isFunction(kval))?kval.call(this,key,this.templateString):kval;
tstr=tstr.replace(_440[i],_447);
}
}
}else{
this.templateNode=this.createNodesFromText(this.templateString,true)[0];
if(!_43e){
ts.node=this.templateNode;
}
}
}
if((!this.templateNode)&&(!_440)){
dojo.debug("DomWidget.buildFromTemplate: could not create template");
return false;
}else{
if(!_440){
node=this.templateNode.cloneNode(true);
if(!node){
return false;
}
}else{
node=this.createNodesFromText(tstr,true)[0];
}
}
this.domNode=node;
this.attachTemplateNodes(this.domNode,this);
if(this.isContainer&&this.containerNode){
var src=this.getFragNodeRef(frag);
if(src){
dojo.dom.moveChildren(src,this.containerNode);
}
}
},attachTemplateNodes:function(_449,_44a){
if(!_44a){
_44a=this;
}
return dojo.widget.attachTemplateNodes(_449,_44a,dojo.widget.getDojoEventsFromStr(this.templateString));
},fillInTemplate:function(){
},destroyRendering:function(){
try{
delete this.domNode;
}
catch(e){
}
},cleanUp:function(){
},getContainerHeight:function(){
dojo.unimplemented("dojo.widget.DomWidget.getContainerHeight");
},getContainerWidth:function(){
dojo.unimplemented("dojo.widget.DomWidget.getContainerWidth");
},createNodesFromText:function(){
dojo.unimplemented("dojo.widget.DomWidget.createNodesFromText");
}});
dojo.provide("dojo.html.common");
dojo.lang.mixin(dojo.html,dojo.dom);
dojo.html.body=function(){
dojo.deprecated("dojo.html.body() moved to dojo.body()","0.5");
return dojo.body();
};
dojo.html.getEventTarget=function(evt){
if(!evt){
evt=dojo.global().event||{};
}
var t=(evt.srcElement?evt.srcElement:(evt.target?evt.target:null));
while((t)&&(t.nodeType!=1)){
t=t.parentNode;
}
return t;
};
dojo.html.getViewport=function(){
var _44d=dojo.global();
var _44e=dojo.doc();
var w=0;
var h=0;
if(!dojo.render.html.opera&&_44d.innerWidth){
w=_44d.innerWidth;
h=_44d.innerHeight;
}else{
if(!dojo.render.html.opera&&dojo.exists(_44e,"documentElement.clientWidth")){
var w2=_44e.documentElement.clientWidth;
if(!w||w2&&w2<w){
w=w2;
}
h=_44e.documentElement.clientHeight;
}else{
if(dojo.body().clientWidth){
w=dojo.body().clientWidth;
h=dojo.body().clientHeight;
}
}
}
return {width:w,height:h};
};
dojo.html.getScroll=function(){
var _452=dojo.global();
var _453=dojo.doc();
var top=_452.pageYOffset||_453.documentElement.scrollTop||dojo.body().scrollTop||0;
var left=_452.pageXOffset||_453.documentElement.scrollLeft||dojo.body().scrollLeft||0;
return {top:top,left:left,offset:{x:left,y:top}};
};
dojo.html.getParentByType=function(node,type){
var _458=dojo.doc();
var _459=dojo.byId(node);
type=type.toLowerCase();
while((_459)&&(_459.nodeName.toLowerCase()!=type)){
if(_459==(_458["body"]||_458["documentElement"])){
return null;
}
_459=_459.parentNode;
}
return _459;
};
dojo.html.getAttribute=function(node,attr){
node=dojo.byId(node);
if((!node)||(!node.getAttribute)){
return null;
}
var ta=typeof attr=="string"?attr:new String(attr);
var v=node.getAttribute(ta.toUpperCase());
if((v)&&(typeof v=="string")&&(v!="")){
return v;
}
if(v&&v.value){
return v.value;
}
if((node.getAttributeNode)&&(node.getAttributeNode(ta))){
return (node.getAttributeNode(ta)).value;
}else{
if(node.getAttribute(ta)){
return node.getAttribute(ta);
}else{
if(node.getAttribute(ta.toLowerCase())){
return node.getAttribute(ta.toLowerCase());
}
}
}
return null;
};
dojo.html.hasAttribute=function(node,attr){
return dojo.html.getAttribute(dojo.byId(node),attr)?true:false;
};
dojo.html.getCursorPosition=function(e){
e=e||dojo.global().event;
var _461={x:0,y:0};
if(e.pageX||e.pageY){
_461.x=e.pageX;
_461.y=e.pageY;
}else{
var de=dojo.doc().documentElement;
var db=dojo.body();
_461.x=e.clientX+((de||db)["scrollLeft"])-((de||db)["clientLeft"]);
_461.y=e.clientY+((de||db)["scrollTop"])-((de||db)["clientTop"]);
}
return _461;
};
dojo.html.isTag=function(node){
node=dojo.byId(node);
if(node&&node.tagName){
for(var i=1;i<arguments.length;i++){
if(node.tagName.toLowerCase()==String(arguments[i]).toLowerCase()){
return String(arguments[i]).toLowerCase();
}
}
}
return "";
};
if(dojo.render.html.ie){
(function(){
var _466=dojo.doc().createElement("script");
_466.src="javascript:'dojo.html.createExternalElement=function(doc, tag){return doc.createElement(tag);}'";
dojo.doc().getElementsByTagName("head")[0].appendChild(_466);
})();
}else{
dojo.html.createExternalElement=function(doc,tag){
return doc.createElement(tag);
};
}
dojo.html._callDeprecated=function(_469,_46a,args,_46c,_46d){
dojo.deprecated("dojo.html."+_469,"replaced by dojo.html."+_46a+"("+(_46c?"node, {"+_46c+": "+_46c+"}":"")+")"+(_46d?"."+_46d:""),"0.5");
var _46e=[];
if(_46c){
var _46f={};
_46f[_46c]=args[1];
_46e.push(args[0]);
_46e.push(_46f);
}else{
_46e=args;
}
var ret=dojo.html[_46a].apply(dojo.html,args);
if(_46d){
return ret[_46d];
}else{
return ret;
}
};
dojo.html.getViewportWidth=function(){
return dojo.html._callDeprecated("getViewportWidth","getViewport",arguments,null,"width");
};
dojo.html.getViewportHeight=function(){
return dojo.html._callDeprecated("getViewportHeight","getViewport",arguments,null,"height");
};
dojo.html.getViewportSize=function(){
return dojo.html._callDeprecated("getViewportSize","getViewport",arguments);
};
dojo.html.getScrollTop=function(){
return dojo.html._callDeprecated("getScrollTop","getScroll",arguments,null,"top");
};
dojo.html.getScrollLeft=function(){
return dojo.html._callDeprecated("getScrollLeft","getScroll",arguments,null,"left");
};
dojo.html.getScrollOffset=function(){
return dojo.html._callDeprecated("getScrollOffset","getScroll",arguments,null,"offset");
};
dojo.provide("dojo.html.layout");
dojo.html.sumAncestorProperties=function(node,prop){
node=dojo.byId(node);
if(!node){
return 0;
}
var _473=0;
while(node){
if(dojo.html.getComputedStyle(node,"position")=="fixed"){
return 0;
}
var val=node[prop];
if(val){
_473+=val-0;
if(node==dojo.body()){
break;
}
}
node=node.parentNode;
}
return _473;
};
dojo.html.setStyleAttributes=function(node,_476){
node=dojo.byId(node);
var _477=_476.replace(/(;)?\s*$/,"").split(";");
for(var i=0;i<_477.length;i++){
var _479=_477[i].split(":");
var name=_479[0].replace(/\s*$/,"").replace(/^\s*/,"").toLowerCase();
var _47b=_479[1].replace(/\s*$/,"").replace(/^\s*/,"");
switch(name){
case "opacity":
dojo.html.setOpacity(node,_47b);
break;
case "content-height":
dojo.html.setContentBox(node,{height:_47b});
break;
case "content-width":
dojo.html.setContentBox(node,{width:_47b});
break;
case "outer-height":
dojo.html.setMarginBox(node,{height:_47b});
break;
case "outer-width":
dojo.html.setMarginBox(node,{width:_47b});
break;
default:
node.style[dojo.html.toCamelCase(name)]=_47b;
}
}
};
dojo.html.boxSizing={MARGIN_BOX:"margin-box",BORDER_BOX:"border-box",PADDING_BOX:"padding-box",CONTENT_BOX:"content-box"};
dojo.html.getAbsolutePosition=dojo.html.abs=function(node,_47d,_47e){
node=dojo.byId(node,node.ownerDocument);
var ret={x:0,y:0};
var bs=dojo.html.boxSizing;
if(!_47e){
_47e=bs.CONTENT_BOX;
}
var _481=1;
var _482;
switch(_47e){
case bs.MARGIN_BOX:
_482=3;
break;
case bs.BORDER_BOX:
_482=2;
break;
case bs.PADDING_BOX:
default:
_482=1;
break;
case bs.CONTENT_BOX:
_482=0;
break;
}
var h=dojo.render.html;
var db=document["body"]||document["documentElement"];
if(h.ie){
with(node.getBoundingClientRect()){
ret.x=left-2;
ret.y=top-2;
}
_481=2;
}else{
if(document.getBoxObjectFor){
try{
var bo=document.getBoxObjectFor(node);
ret.x=bo.x-dojo.html.sumAncestorProperties(node,"scrollLeft");
ret.y=bo.y-dojo.html.sumAncestorProperties(node,"scrollTop");
}
catch(e){
}
}else{
if(node["offsetParent"]){
var _486;
if((h.safari)&&(node.style.getPropertyValue("position")=="absolute")&&(node.parentNode==db)){
_486=db;
}else{
_486=db.parentNode;
}
if(h.opera){
_481=2;
}
if(node.parentNode!=db){
var nd=node;
ret.x-=dojo.html.sumAncestorProperties(nd,"scrollLeft");
ret.y-=dojo.html.sumAncestorProperties(nd,"scrollTop");
}
var _488=node;
do{
var n=_488["offsetLeft"];
if(!h.opera||n>0){
ret.x+=isNaN(n)?0:n;
}
var m=_488["offsetTop"];
ret.y+=isNaN(m)?0:m;
_488=_488.offsetParent;
}while((_488!=_486)&&(_488!=null));
}else{
if(node["x"]&&node["y"]){
ret.x+=isNaN(node.x)?0:node.x;
ret.y+=isNaN(node.y)?0:node.y;
}
}
}
}
if(_47d){
var _48b=dojo.html.getScroll();
ret.y+=_48b.top;
ret.x+=_48b.left;
}
var _48c=[dojo.html.getPaddingExtent,dojo.html.getBorderExtent,dojo.html.getMarginExtent];
if(_481>_482){
for(var i=_482;i<_481;++i){
ret.y+=_48c[i](node,"top");
ret.x+=_48c[i](node,"left");
}
}else{
if(_481<_482){
for(var i=_482;i>_481;--i){
ret.y-=_48c[i-1](node,"top");
ret.x-=_48c[i-1](node,"left");
}
}
}
ret.top=ret.y;
ret.left=ret.x;
return ret;
};
dojo.html.isPositionAbsolute=function(node){
return (dojo.html.getComputedStyle(node,"position")=="absolute");
};
dojo.html._sumPixelValues=function(node,_490,_491){
var _492=0;
for(var x=0;x<_490.length;x++){
_492+=dojo.html.getPixelValue(node,_490[x],_491);
}
return _492;
};
dojo.html.getMargin=function(node){
return {width:dojo.html._sumPixelValues(node,["margin-left","margin-right"],(dojo.html.getComputedStyle(node,"position")=="absolute")),height:dojo.html._sumPixelValues(node,["margin-top","margin-bottom"],(dojo.html.getComputedStyle(node,"position")=="absolute"))};
};
dojo.html.getBorder=function(node){
return {width:dojo.html.getBorderExtent(node,"left")+dojo.html.getBorderExtent(node,"right"),height:dojo.html.getBorderExtent(node,"top")+dojo.html.getBorderExtent(node,"bottom")};
};
dojo.html.getBorderExtent=function(node,side){
return (dojo.html.getStyle(node,"border-"+side+"-style")=="none"?0:dojo.html.getPixelValue(node,"border-"+side+"-width"));
};
dojo.html.getMarginExtent=function(node,side){
return dojo.html._sumPixelValues(node,["margin-"+side],dojo.html.isPositionAbsolute(node));
};
dojo.html.getPaddingExtent=function(node,side){
return dojo.html._sumPixelValues(node,["padding-"+side],true);
};
dojo.html.getPadding=function(node){
return {width:dojo.html._sumPixelValues(node,["padding-left","padding-right"],true),height:dojo.html._sumPixelValues(node,["padding-top","padding-bottom"],true)};
};
dojo.html.getPadBorder=function(node){
var pad=dojo.html.getPadding(node);
var _49f=dojo.html.getBorder(node);
return {width:pad.width+_49f.width,height:pad.height+_49f.height};
};
dojo.html.getBoxSizing=function(node){
var h=dojo.render.html;
var bs=dojo.html.boxSizing;
if((h.ie)||(h.opera)){
var cm=document["compatMode"];
if((cm=="BackCompat")||(cm=="QuirksMode")){
return bs.BORDER_BOX;
}else{
return bs.CONTENT_BOX;
}
}else{
if(arguments.length==0){
node=document.documentElement;
}
var _4a4=dojo.html.getStyle(node,"-moz-box-sizing");
if(!_4a4){
_4a4=dojo.html.getStyle(node,"box-sizing");
}
return (_4a4?_4a4:bs.CONTENT_BOX);
}
};
dojo.html.isBorderBox=function(node){
return (dojo.html.getBoxSizing(node)==dojo.html.boxSizing.BORDER_BOX);
};
dojo.html.getBorderBox=function(node){
node=dojo.byId(node);
return {width:node.offsetWidth,height:node.offsetHeight};
};
dojo.html.getPaddingBox=function(node){
var box=dojo.html.getBorderBox(node);
var _4a9=dojo.html.getBorder(node);
return {width:box.width-_4a9.width,height:box.height-_4a9.height};
};
dojo.html.getContentBox=function(node){
node=dojo.byId(node);
var _4ab=dojo.html.getPadBorder(node);
return {width:node.offsetWidth-_4ab.width,height:node.offsetHeight-_4ab.height};
};
dojo.html.setContentBox=function(node,args){
node=dojo.byId(node);
var _4ae=0;
var _4af=0;
var isbb=dojo.html.isBorderBox(node);
var _4b1=(isbb?dojo.html.getPadBorder(node):{width:0,height:0});
var ret={};
if(typeof args.width!=undefined){
_4ae=args.width+_4b1.width;
ret.width=dojo.html.setPositivePixelValue(node,"width",_4ae);
}
if(typeof args.height!=undefined){
_4af=args.height+_4b1.height;
ret.height=dojo.html.setPositivePixelValue(node,"height",_4af);
}
return ret;
};
dojo.html.getMarginBox=function(node){
var _4b4=dojo.html.getBorderBox(node);
var _4b5=dojo.html.getMargin(node);
return {width:_4b4.width+_4b5.width,height:_4b4.height+_4b5.height};
};
dojo.html.setMarginBox=function(node,args){
node=dojo.byId(node);
var _4b8=0;
var _4b9=0;
var isbb=dojo.html.isBorderBox(node);
var _4bb=(!isbb?dojo.html.getPadBorder(node):{width:0,height:0});
var _4bc=dojo.html.getMargin(node);
var ret={};
if(typeof args.width!=undefined){
_4b8=args.width-_4bb.width;
_4b8-=_4bc.width;
ret.width=dojo.html.setPositivePixelValue(node,"width",_4b8);
}
if(typeof args.height!=undefined){
_4b9=args.height-_4bb.height;
_4b9-=_4bc.height;
ret.height=dojo.html.setPositivePixelValue(node,"height",_4b9);
}
return ret;
};
dojo.html.getElementBox=function(node,type){
var bs=dojo.html.boxSizing;
switch(type){
case bs.MARGIN_BOX:
return dojo.html.getMarginBox(node);
case bs.BORDER_BOX:
return dojo.html.getBorderBox(node);
case bs.PADDING_BOX:
return dojo.html.getPaddingBox(node);
case bs.CONTENT_BOX:
default:
return dojo.html.getContentBox(node);
}
};
dojo.html.toCoordinateObject=dojo.html.toCoordinateArray=function(_4c1,_4c2){
if(_4c1 instanceof Array||typeof _4c1=="array"){
dojo.deprecated("dojo.html.toCoordinateArray","use dojo.html.toCoordinateObject({left: , top: , width: , height: }) instead","0.5");
while(_4c1.length<4){
_4c1.push(0);
}
while(_4c1.length>4){
_4c1.pop();
}
var ret={left:_4c1[0],top:_4c1[1],width:_4c1[2],height:_4c1[3]};
}else{
if(!_4c1.nodeType&&!(_4c1 instanceof String||typeof _4c1=="string")&&("width" in _4c1||"height" in _4c1||"left" in _4c1||"x" in _4c1||"top" in _4c1||"y" in _4c1)){
var ret={left:_4c1.left||_4c1.x||0,top:_4c1.top||_4c1.y||0,width:_4c1.width||0,height:_4c1.height||0};
}else{
var node=dojo.byId(_4c1);
var pos=dojo.html.abs(node,_4c2);
var _4c6=dojo.html.getBorderBox(node);
var ret={left:pos.left,top:pos.top,width:_4c6.width,height:_4c6.height};
}
}
ret.x=ret.left;
ret.y=ret.top;
return ret;
};
dojo.html.setMarginBoxWidth=dojo.html.setOuterWidth=function(node,_4c8){
return dojo.html._callDeprecated("setMarginBoxWidth","setMarginBox",arguments,"width");
};
dojo.html.setMarginBoxHeight=dojo.html.setOuterHeight=function(){
return dojo.html._callDeprecated("setMarginBoxHeight","setMarginBox",arguments,"height");
};
dojo.html.getMarginBoxWidth=dojo.html.getOuterWidth=function(){
return dojo.html._callDeprecated("getMarginBoxWidth","getMarginBox",arguments,null,"width");
};
dojo.html.getMarginBoxHeight=dojo.html.getOuterHeight=function(){
return dojo.html._callDeprecated("getMarginBoxHeight","getMarginBox",arguments,null,"height");
};
dojo.html.getTotalOffset=function(node,type,_4cb){
return dojo.html._callDeprecated("getTotalOffset","getAbsolutePosition",arguments,null,type);
};
dojo.html.getAbsoluteX=function(node,_4cd){
return dojo.html._callDeprecated("getAbsoluteX","getAbsolutePosition",arguments,null,"x");
};
dojo.html.getAbsoluteY=function(node,_4cf){
return dojo.html._callDeprecated("getAbsoluteY","getAbsolutePosition",arguments,null,"y");
};
dojo.html.totalOffsetLeft=function(node,_4d1){
return dojo.html._callDeprecated("totalOffsetLeft","getAbsolutePosition",arguments,null,"left");
};
dojo.html.totalOffsetTop=function(node,_4d3){
return dojo.html._callDeprecated("totalOffsetTop","getAbsolutePosition",arguments,null,"top");
};
dojo.html.getMarginWidth=function(node){
return dojo.html._callDeprecated("getMarginWidth","getMargin",arguments,null,"width");
};
dojo.html.getMarginHeight=function(node){
return dojo.html._callDeprecated("getMarginHeight","getMargin",arguments,null,"height");
};
dojo.html.getBorderWidth=function(node){
return dojo.html._callDeprecated("getBorderWidth","getBorder",arguments,null,"width");
};
dojo.html.getBorderHeight=function(node){
return dojo.html._callDeprecated("getBorderHeight","getBorder",arguments,null,"height");
};
dojo.html.getPaddingWidth=function(node){
return dojo.html._callDeprecated("getPaddingWidth","getPadding",arguments,null,"width");
};
dojo.html.getPaddingHeight=function(node){
return dojo.html._callDeprecated("getPaddingHeight","getPadding",arguments,null,"height");
};
dojo.html.getPadBorderWidth=function(node){
return dojo.html._callDeprecated("getPadBorderWidth","getPadBorder",arguments,null,"width");
};
dojo.html.getPadBorderHeight=function(node){
return dojo.html._callDeprecated("getPadBorderHeight","getPadBorder",arguments,null,"height");
};
dojo.html.getBorderBoxWidth=dojo.html.getInnerWidth=function(){
return dojo.html._callDeprecated("getBorderBoxWidth","getBorderBox",arguments,null,"width");
};
dojo.html.getBorderBoxHeight=dojo.html.getInnerHeight=function(){
return dojo.html._callDeprecated("getBorderBoxHeight","getBorderBox",arguments,null,"height");
};
dojo.html.getContentBoxWidth=dojo.html.getContentWidth=function(){
return dojo.html._callDeprecated("getContentBoxWidth","getContentBox",arguments,null,"width");
};
dojo.html.getContentBoxHeight=dojo.html.getContentHeight=function(){
return dojo.html._callDeprecated("getContentBoxHeight","getContentBox",arguments,null,"height");
};
dojo.html.setContentBoxWidth=dojo.html.setContentWidth=function(node,_4dd){
return dojo.html._callDeprecated("setContentBoxWidth","setContentBox",arguments,"width");
};
dojo.html.setContentBoxHeight=dojo.html.setContentHeight=function(node,_4df){
return dojo.html._callDeprecated("setContentBoxHeight","setContentBox",arguments,"height");
};
dojo.provide("dojo.html.util");
dojo.html.getElementWindow=function(_4e0){
return dojo.html.getDocumentWindow(_4e0.ownerDocument);
};
dojo.html.getDocumentWindow=function(doc){
if(dojo.render.html.safari&&!doc._parentWindow){
var fix=function(win){
win.document._parentWindow=win;
for(var i=0;i<win.frames.length;i++){
fix(win.frames[i]);
}
};
fix(window.top);
}
if(dojo.render.html.ie&&window!==document.parentWindow&&!doc._parentWindow){
doc.parentWindow.execScript("document._parentWindow = window;","Javascript");
}
return doc._parentWindow||doc.parentWindow||doc.defaultView;
};
dojo.html.gravity=function(node,e){
node=dojo.byId(node);
var _4e7=dojo.html.getCursorPosition(e);
with(dojo.html){
var _4e8=getAbsolutePosition(node,true);
var bb=getBorderBox(node);
var _4ea=_4e8.x+(bb.width/2);
var _4eb=_4e8.y+(bb.height/2);
}
with(dojo.html.gravity){
return ((_4e7.x<_4ea?WEST:EAST)|(_4e7.y<_4eb?NORTH:SOUTH));
}
};
dojo.html.gravity.NORTH=1;
dojo.html.gravity.SOUTH=1<<1;
dojo.html.gravity.EAST=1<<2;
dojo.html.gravity.WEST=1<<3;
dojo.html.overElement=function(_4ec,e){
_4ec=dojo.byId(_4ec);
var _4ee=dojo.html.getCursorPosition(e);
with(dojo.html){
var bb=getBorderBox(_4ec);
var _4f0=getAbsolutePosition(_4ec,true);
var top=_4f0.y;
var _4f2=top+bb.height;
var left=_4f0.x;
var _4f4=left+bb.width;
}
return (_4ee.x>=left&&_4ee.x<=_4f4&&_4ee.y>=top&&_4ee.y<=_4f2);
};
dojo.html.renderedTextContent=function(node){
node=dojo.byId(node);
var _4f6="";
if(node==null){
return _4f6;
}
for(var i=0;i<node.childNodes.length;i++){
switch(node.childNodes[i].nodeType){
case 1:
case 5:
var _4f8="unknown";
try{
_4f8=dojo.html.getStyle(node.childNodes[i],"display");
}
catch(E){
}
switch(_4f8){
case "block":
case "list-item":
case "run-in":
case "table":
case "table-row-group":
case "table-header-group":
case "table-footer-group":
case "table-row":
case "table-column-group":
case "table-column":
case "table-cell":
case "table-caption":
_4f6+="\n";
_4f6+=dojo.html.renderedTextContent(node.childNodes[i]);
_4f6+="\n";
break;
case "none":
break;
default:
if(node.childNodes[i].tagName&&node.childNodes[i].tagName.toLowerCase()=="br"){
_4f6+="\n";
}else{
_4f6+=dojo.html.renderedTextContent(node.childNodes[i]);
}
break;
}
break;
case 3:
case 2:
case 4:
var text=node.childNodes[i].nodeValue;
var _4fa="unknown";
try{
_4fa=dojo.html.getStyle(node,"text-transform");
}
catch(E){
}
switch(_4fa){
case "capitalize":
var _4fb=text.split(" ");
for(var i=0;i<_4fb.length;i++){
_4fb[i]=_4fb[i].charAt(0).toUpperCase()+_4fb[i].substring(1);
}
text=_4fb.join(" ");
break;
case "uppercase":
text=text.toUpperCase();
break;
case "lowercase":
text=text.toLowerCase();
break;
default:
break;
}
switch(_4fa){
case "nowrap":
break;
case "pre-wrap":
break;
case "pre-line":
break;
case "pre":
break;
default:
text=text.replace(/\s+/," ");
if(/\s$/.test(_4f6)){
text.replace(/^\s/,"");
}
break;
}
_4f6+=text;
break;
default:
break;
}
}
return _4f6;
};
dojo.html.createNodesFromText=function(txt,trim){
if(trim){
txt=txt.replace(/^\s+|\s+$/g,"");
}
var tn=dojo.doc().createElement("div");
tn.style.visibility="hidden";
dojo.body().appendChild(tn);
var _4ff="none";
if((/^<t[dh][\s\r\n>]/i).test(txt.replace(/^\s+/))){
txt="<table><tbody><tr>"+txt+"</tr></tbody></table>";
_4ff="cell";
}else{
if((/^<tr[\s\r\n>]/i).test(txt.replace(/^\s+/))){
txt="<table><tbody>"+txt+"</tbody></table>";
_4ff="row";
}else{
if((/^<(thead|tbody|tfoot)[\s\r\n>]/i).test(txt.replace(/^\s+/))){
txt="<table>"+txt+"</table>";
_4ff="section";
}
}
}
tn.innerHTML=txt;
if(tn["normalize"]){
tn.normalize();
}
var _500=null;
switch(_4ff){
case "cell":
_500=tn.getElementsByTagName("tr")[0];
break;
case "row":
_500=tn.getElementsByTagName("tbody")[0];
break;
case "section":
_500=tn.getElementsByTagName("table")[0];
break;
default:
_500=tn;
break;
}
var _501=[];
for(var x=0;x<_500.childNodes.length;x++){
_501.push(_500.childNodes[x].cloneNode(true));
}
tn.style.display="none";
dojo.body().removeChild(tn);
return _501;
};
dojo.html.placeOnScreen=function(node,_504,_505,_506,_507,_508,_509){
if(_504 instanceof Array||typeof _504=="array"){
_509=_508;
_508=_507;
_507=_506;
_506=_505;
_505=_504[1];
_504=_504[0];
}
if(_508 instanceof String||typeof _508=="string"){
_508=_508.split(",");
}
if(!isNaN(_506)){
_506=[Number(_506),Number(_506)];
}else{
if(!(_506 instanceof Array||typeof _506=="array")){
_506=[0,0];
}
}
var _50a=dojo.html.getScroll().offset;
var view=dojo.html.getViewport();
node=dojo.byId(node);
var _50c=node.style.display;
node.style.display="";
var bb=dojo.html.getBorderBox(node);
var w=bb.width;
var h=bb.height;
node.style.display=_50c;
if(!(_508 instanceof Array||typeof _508=="array")){
_508=["TL"];
}
var _510,besty,bestDistance=Infinity;
for(var _511=0;_511<_508.length;++_511){
var _512=_508[_511];
var _513=true;
var tryX=_504-(_512.charAt(1)=="L"?0:w)+_506[0]*(_512.charAt(1)=="L"?1:-1);
var tryY=_505-(_512.charAt(0)=="T"?0:h)+_506[1]*(_512.charAt(0)=="T"?1:-1);
if(_507){
tryX-=_50a.x;
tryY-=_50a.y;
}
var x=tryX+w;
if(x>view.width){
x=view.width-w;
_513=false;
}else{
x=tryX;
}
x=Math.max(_506[0],x)+_50a.x;
var y=tryY+h;
if(y>view.height){
y=view.height-h;
_513=false;
}else{
y=tryY;
}
y=Math.max(_506[1],y)+_50a.y;
if(_513){
_510=x;
besty=y;
bestDistance=0;
break;
}else{
var dist=Math.pow(x-tryX-_50a.x,2)+Math.pow(y-tryY-_50a.y,2);
if(bestDistance>dist){
bestDistance=dist;
_510=x;
besty=y;
}
}
}
if(!_509){
node.style.left=_510+"px";
node.style.top=besty+"px";
}
return {left:_510,top:besty,x:_510,y:besty,dist:bestDistance};
};
dojo.html.placeOnScreenPoint=function(node,_51a,_51b,_51c,_51d){
dojo.deprecated("dojo.html.placeOnScreenPoint","use dojo.html.placeOnScreen() instead","0.5");
return dojo.html.placeOnScreen(node,_51a,_51b,_51c,_51d,["TL","TR","BL","BR"]);
};
dojo.html.placeOnScreenAroundElement=function(node,_51f,_520,_521,_522,_523){
var best,bestDistance=Infinity;
_51f=dojo.byId(_51f);
var _525=_51f.style.display;
_51f.style.display="";
var mb=dojo.html.getElementBox(_51f,_521);
var _527=mb.width;
var _528=mb.height;
var _529=dojo.html.getAbsolutePosition(_51f,true,_521);
_51f.style.display=_525;
for(var _52a in _522){
var pos,desiredX,desiredY;
var _52c=_522[_52a];
desiredX=_529.x+(_52a.charAt(1)=="L"?0:_527);
desiredY=_529.y+(_52a.charAt(0)=="T"?0:_528);
pos=dojo.html.placeOnScreen(node,desiredX,desiredY,_520,true,_52c,true);
if(pos.dist==0){
best=pos;
break;
}else{
if(bestDistance>pos.dist){
bestDistance=pos.dist;
best=pos;
}
}
}
if(!_523){
node.style.left=best.left+"px";
node.style.top=best.top+"px";
}
return best;
};
dojo.html.scrollIntoView=function(node){
if(!node){
return;
}
if(dojo.render.html.ie){
if(dojo.html.getBorderBox(node.parentNode).height<node.parentNode.scrollHeight){
node.scrollIntoView(false);
}
}else{
if(dojo.render.html.mozilla){
node.scrollIntoView(false);
}else{
var _52e=node.parentNode;
var _52f=_52e.scrollTop+dojo.html.getBorderBox(_52e).height;
var _530=node.offsetTop+dojo.html.getMarginBox(node).height;
if(_52f<_530){
_52e.scrollTop+=(_530-_52f);
}else{
if(_52e.scrollTop>node.offsetTop){
_52e.scrollTop-=(_52e.scrollTop-node.offsetTop);
}
}
}
}
};
dojo.provide("dojo.html.display");
dojo.html._toggle=function(node,_532,_533){
node=dojo.byId(node);
_533(node,!_532(node));
return _532(node);
};
dojo.html.show=function(node){
node=dojo.byId(node);
if(dojo.html.getStyleProperty(node,"display")=="none"){
dojo.html.setStyle(node,"display",(node.dojoDisplayCache||""));
node.dojoDisplayCache=undefined;
}
};
dojo.html.hide=function(node){
node=dojo.byId(node);
if(typeof node["dojoDisplayCache"]=="undefined"){
var d=dojo.html.getStyleProperty(node,"display");
if(d!="none"){
node.dojoDisplayCache=d;
}
}
dojo.html.setStyle(node,"display","none");
};
dojo.html.setShowing=function(node,_538){
dojo.html[(_538?"show":"hide")](node);
};
dojo.html.isShowing=function(node){
return (dojo.html.getStyleProperty(node,"display")!="none");
};
dojo.html.toggleShowing=function(node){
return dojo.html._toggle(node,dojo.html.isShowing,dojo.html.setShowing);
};
dojo.html.displayMap={tr:"",td:"",th:"",img:"inline",span:"inline",input:"inline",button:"inline"};
dojo.html.suggestDisplayByTagName=function(node){
node=dojo.byId(node);
if(node&&node.tagName){
var tag=node.tagName.toLowerCase();
return (tag in dojo.html.displayMap?dojo.html.displayMap[tag]:"block");
}
};
dojo.html.setDisplay=function(node,_53e){
dojo.html.setStyle(node,"display",((_53e instanceof String||typeof _53e=="string")?_53e:(_53e?dojo.html.suggestDisplayByTagName(node):"none")));
};
dojo.html.isDisplayed=function(node){
return (dojo.html.getComputedStyle(node,"display")!="none");
};
dojo.html.toggleDisplay=function(node){
return dojo.html._toggle(node,dojo.html.isDisplayed,dojo.html.setDisplay);
};
dojo.html.setVisibility=function(node,_542){
dojo.html.setStyle(node,"visibility",((_542 instanceof String||typeof _542=="string")?_542:(_542?"visible":"hidden")));
};
dojo.html.isVisible=function(node){
return (dojo.html.getComputedStyle(node,"visibility")!="hidden");
};
dojo.html.toggleVisibility=function(node){
return dojo.html._toggle(node,dojo.html.isVisible,dojo.html.setVisibility);
};
dojo.html.setOpacity=function(node,_546,_547){
node=dojo.byId(node);
var h=dojo.render.html;
if(!_547){
if(_546>=1){
if(h.ie){
dojo.html.clearOpacity(node);
return;
}else{
_546=0.999999;
}
}else{
if(_546<0){
_546=0;
}
}
}
if(h.ie){
if(node.nodeName.toLowerCase()=="tr"){
var tds=node.getElementsByTagName("td");
for(var x=0;x<tds.length;x++){
tds[x].style.filter="Alpha(Opacity="+_546*100+")";
}
}
node.style.filter="Alpha(Opacity="+_546*100+")";
}else{
if(h.moz){
node.style.opacity=_546;
node.style.MozOpacity=_546;
}else{
if(h.safari){
node.style.opacity=_546;
node.style.KhtmlOpacity=_546;
}else{
node.style.opacity=_546;
}
}
}
};
dojo.html.clearOpacity=function clearOpacity(node){
node=dojo.byId(node);
var ns=node.style;
var h=dojo.render.html;
if(h.ie){
try{
if(node.filters&&node.filters.alpha){
ns.filter="";
}
}
catch(e){
}
}else{
if(h.moz){
ns.opacity=1;
ns.MozOpacity=1;
}else{
if(h.safari){
ns.opacity=1;
ns.KhtmlOpacity=1;
}else{
ns.opacity=1;
}
}
}
};
dojo.html.getOpacity=function getOpacity(node){
node=dojo.byId(node);
var h=dojo.render.html;
if(h.ie){
var opac=(node.filters&&node.filters.alpha&&typeof node.filters.alpha.opacity=="number"?node.filters.alpha.opacity:100)/100;
}else{
var opac=node.style.opacity||node.style.MozOpacity||node.style.KhtmlOpacity||1;
}
return opac>=0.999999?1:Number(opac);
};
dojo.provide("dojo.lfx.Animation");
dojo.provide("dojo.lfx.Line");
dojo.lfx.Line=function(_551,end){
this.start=_551;
this.end=end;
if(dojo.lang.isArray(_551)){
var diff=[];
dojo.lang.forEach(this.start,function(s,i){
diff[i]=this.end[i]-s;
},this);
this.getValue=function(n){
var res=[];
dojo.lang.forEach(this.start,function(s,i){
res[i]=(diff[i]*n)+s;
},this);
return res;
};
}else{
var diff=end-_551;
this.getValue=function(n){
return (diff*n)+this.start;
};
}
};
dojo.lfx.easeIn=function(n){
return Math.pow(n,3);
};
dojo.lfx.easeOut=function(n){
return (1-Math.pow(1-n,3));
};
dojo.lfx.easeInOut=function(n){
return ((3*Math.pow(n,2))-(2*Math.pow(n,3)));
};
dojo.lfx.IAnimation=function(){
};
dojo.lang.extend(dojo.lfx.IAnimation,{curve:null,duration:1000,easing:null,repeatCount:0,rate:25,handler:null,beforeBegin:null,onBegin:null,onAnimate:null,onEnd:null,onPlay:null,onPause:null,onStop:null,play:null,pause:null,stop:null,fire:function(evt,args){
if(this[evt]){
this[evt].apply(this,(args||[]));
}
},_active:false,_paused:false});
dojo.lfx.Animation=function(_560,_561,_562,_563,_564,rate){
dojo.lfx.IAnimation.call(this);
if(dojo.lang.isNumber(_560)||(!_560&&_561.getValue)){
rate=_564;
_564=_563;
_563=_562;
_562=_561;
_561=_560;
_560=null;
}else{
if(_560.getValue||dojo.lang.isArray(_560)){
rate=_563;
_564=_562;
_563=_561;
_562=_560;
_561=null;
_560=null;
}
}
if(dojo.lang.isArray(_562)){
this.curve=new dojo.lfx.Line(_562[0],_562[1]);
}else{
this.curve=_562;
}
if(_561!=null&&_561>0){
this.duration=_561;
}
if(_564){
this.repeatCount=_564;
}
if(rate){
this.rate=rate;
}
if(_560){
this.handler=_560.handler;
this.beforeBegin=_560.beforeBegin;
this.onBegin=_560.onBegin;
this.onEnd=_560.onEnd;
this.onPlay=_560.onPlay;
this.onPause=_560.onPause;
this.onStop=_560.onStop;
this.onAnimate=_560.onAnimate;
}
if(_563&&dojo.lang.isFunction(_563)){
this.easing=_563;
}
};
dojo.inherits(dojo.lfx.Animation,dojo.lfx.IAnimation);
dojo.lang.extend(dojo.lfx.Animation,{_startTime:null,_endTime:null,_timer:null,_percent:0,_startRepeatCount:0,play:function(_566,_567){
if(_567){
clearTimeout(this._timer);
this._active=false;
this._paused=false;
this._percent=0;
}else{
if(this._active&&!this._paused){
return this;
}
}
this.fire("handler",["beforeBegin"]);
this.fire("beforeBegin");
if(_566>0){
setTimeout(dojo.lang.hitch(this,function(){
this.play(null,_567);
}),_566);
return this;
}
this._startTime=new Date().valueOf();
if(this._paused){
this._startTime-=(this.duration*this._percent/100);
}
this._endTime=this._startTime+this.duration;
this._active=true;
this._paused=false;
var step=this._percent/100;
var _569=this.curve.getValue(step);
if(this._percent==0){
if(!this._startRepeatCount){
this._startRepeatCount=this.repeatCount;
}
this.fire("handler",["begin",_569]);
this.fire("onBegin",[_569]);
}
this.fire("handler",["play",_569]);
this.fire("onPlay",[_569]);
this._cycle();
return this;
},pause:function(){
clearTimeout(this._timer);
if(!this._active){
return this;
}
this._paused=true;
var _56a=this.curve.getValue(this._percent/100);
this.fire("handler",["pause",_56a]);
this.fire("onPause",[_56a]);
return this;
},gotoPercent:function(pct,_56c){
clearTimeout(this._timer);
this._active=true;
this._paused=true;
this._percent=pct;
if(_56c){
this.play();
}
},stop:function(_56d){
clearTimeout(this._timer);
var step=this._percent/100;
if(_56d){
step=1;
}
var _56f=this.curve.getValue(step);
this.fire("handler",["stop",_56f]);
this.fire("onStop",[_56f]);
this._active=false;
this._paused=false;
return this;
},status:function(){
if(this._active){
return this._paused?"paused":"playing";
}else{
return "stopped";
}
},_cycle:function(){
clearTimeout(this._timer);
if(this._active){
var curr=new Date().valueOf();
var step=(curr-this._startTime)/(this._endTime-this._startTime);
if(step>=1){
step=1;
this._percent=100;
}else{
this._percent=step*100;
}
if((this.easing)&&(dojo.lang.isFunction(this.easing))){
step=this.easing(step);
}
var _572=this.curve.getValue(step);
this.fire("handler",["animate",_572]);
this.fire("onAnimate",[_572]);
if(step<1){
this._timer=setTimeout(dojo.lang.hitch(this,"_cycle"),this.rate);
}else{
this._active=false;
this.fire("handler",["end"]);
this.fire("onEnd");
if(this.repeatCount>0){
this.repeatCount--;
this.play(null,true);
}else{
if(this.repeatCount==-1){
this.play(null,true);
}else{
if(this._startRepeatCount){
this.repeatCount=this._startRepeatCount;
this._startRepeatCount=0;
}
}
}
}
}
return this;
}});
dojo.lfx.Combine=function(){
dojo.lfx.IAnimation.call(this);
this._anims=[];
this._animsEnded=0;
var _573=arguments;
if(_573.length==1&&(dojo.lang.isArray(_573[0])||dojo.lang.isArrayLike(_573[0]))){
_573=_573[0];
}
var _574=this;
dojo.lang.forEach(_573,function(anim){
_574._anims.push(anim);
var _576=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_576();
_574._onAnimsEnded();
};
});
};
dojo.inherits(dojo.lfx.Combine,dojo.lfx.IAnimation);
dojo.lang.extend(dojo.lfx.Combine,{_animsEnded:0,play:function(_577,_578){
if(!this._anims.length){
return this;
}
this.fire("beforeBegin");
if(_577>0){
setTimeout(dojo.lang.hitch(this,function(){
this.play(null,_578);
}),_577);
return this;
}
if(_578||this._anims[0].percent==0){
this.fire("onBegin");
}
this.fire("onPlay");
this._animsCall("play",null,_578);
return this;
},pause:function(){
this.fire("onPause");
this._animsCall("pause");
return this;
},stop:function(_579){
this.fire("onStop");
this._animsCall("stop",_579);
return this;
},_onAnimsEnded:function(){
this._animsEnded++;
if(this._animsEnded>=this._anims.length){
this.fire("onEnd");
}
return this;
},_animsCall:function(_57a){
var args=[];
if(arguments.length>1){
for(var i=1;i<arguments.length;i++){
args.push(arguments[i]);
}
}
var _57d=this;
dojo.lang.forEach(this._anims,function(anim){
anim[_57a](args);
},_57d);
return this;
}});
dojo.lfx.Chain=function(){
dojo.lfx.IAnimation.call(this);
this._anims=[];
this._currAnim=-1;
var _57f=arguments;
if(_57f.length==1&&(dojo.lang.isArray(_57f[0])||dojo.lang.isArrayLike(_57f[0]))){
_57f=_57f[0];
}
var _580=this;
dojo.lang.forEach(_57f,function(anim,i,_583){
_580._anims.push(anim);
var _584=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
if(i<_583.length-1){
anim.onEnd=function(){
_584();
_580._playNext();
};
}else{
anim.onEnd=function(){
_584();
_580.fire("onEnd");
};
}
},_580);
};
dojo.inherits(dojo.lfx.Chain,dojo.lfx.IAnimation);
dojo.lang.extend(dojo.lfx.Chain,{_currAnim:-1,play:function(_585,_586){
if(!this._anims.length){
return this;
}
if(_586||!this._anims[this._currAnim]){
this._currAnim=0;
}
var _587=this._anims[this._currAnim];
this.fire("beforeBegin");
if(_585>0){
setTimeout(dojo.lang.hitch(this,function(){
this.play(null,_586);
}),_585);
return this;
}
if(_587){
if(this._currAnim==0){
this.fire("handler",["begin",this._currAnim]);
this.fire("onBegin",[this._currAnim]);
}
this.fire("onPlay",[this._currAnim]);
_587.play(null,_586);
}
return this;
},pause:function(){
if(this._anims[this._currAnim]){
this._anims[this._currAnim].pause();
this.fire("onPause",[this._currAnim]);
}
return this;
},playPause:function(){
if(this._anims.length==0){
return this;
}
if(this._currAnim==-1){
this._currAnim=0;
}
var _588=this._anims[this._currAnim];
if(_588){
if(!_588._active||_588._paused){
this.play();
}else{
this.pause();
}
}
return this;
},stop:function(){
var _589=this._anims[this._currAnim];
if(_589){
_589.stop();
this.fire("onStop",[this._currAnim]);
}
return _589;
},_playNext:function(){
if(this._currAnim==-1||this._anims.length==0){
return this;
}
this._currAnim++;
if(this._anims[this._currAnim]){
this._anims[this._currAnim].play(null,true);
}
return this;
}});
dojo.lfx.combine=function(){
var _58a=arguments;
if(dojo.lang.isArray(arguments[0])){
_58a=arguments[0];
}
return new dojo.lfx.Combine(_58a);
};
dojo.lfx.chain=function(){
var _58b=arguments;
if(dojo.lang.isArray(arguments[0])){
_58b=arguments[0];
}
return new dojo.lfx.Chain(_58b);
};
dojo.provide("dojo.graphics.color");
dojo.graphics.color.Color=function(r,g,b,a){
if(dojo.lang.isArray(r)){
this.r=r[0];
this.g=r[1];
this.b=r[2];
this.a=r[3]||1;
}else{
if(dojo.lang.isString(r)){
var rgb=dojo.graphics.color.extractRGB(r);
this.r=rgb[0];
this.g=rgb[1];
this.b=rgb[2];
this.a=g||1;
}else{
if(r instanceof dojo.graphics.color.Color){
this.r=r.r;
this.b=r.b;
this.g=r.g;
this.a=r.a;
}else{
this.r=r;
this.g=g;
this.b=b;
this.a=a;
}
}
}
};
dojo.graphics.color.Color.fromArray=function(arr){
return new dojo.graphics.color.Color(arr[0],arr[1],arr[2],arr[3]);
};
dojo.lang.extend(dojo.graphics.color.Color,{toRgb:function(_592){
if(_592){
return this.toRgba();
}else{
return [this.r,this.g,this.b];
}
},toRgba:function(){
return [this.r,this.g,this.b,this.a];
},toHex:function(){
return dojo.graphics.color.rgb2hex(this.toRgb());
},toCss:function(){
return "rgb("+this.toRgb().join()+")";
},toString:function(){
return this.toHex();
},blend:function(_593,_594){
return dojo.graphics.color.blend(this.toRgb(),new dojo.graphics.color.Color(_593).toRgb(),_594);
}});
dojo.graphics.color.named={white:[255,255,255],black:[0,0,0],red:[255,0,0],green:[0,255,0],blue:[0,0,255],navy:[0,0,128],gray:[128,128,128],silver:[192,192,192]};
dojo.graphics.color.blend=function(a,b,_597){
if(typeof a=="string"){
return dojo.graphics.color.blendHex(a,b,_597);
}
if(!_597){
_597=0;
}else{
if(_597>1){
_597=1;
}else{
if(_597<-1){
_597=-1;
}
}
}
var c=new Array(3);
for(var i=0;i<3;i++){
var half=Math.abs(a[i]-b[i])/2;
c[i]=Math.floor(Math.min(a[i],b[i])+half+(half*_597));
}
return c;
};
dojo.graphics.color.blendHex=function(a,b,_59d){
return dojo.graphics.color.rgb2hex(dojo.graphics.color.blend(dojo.graphics.color.hex2rgb(a),dojo.graphics.color.hex2rgb(b),_59d));
};
dojo.graphics.color.extractRGB=function(_59e){
var hex="0123456789abcdef";
_59e=_59e.toLowerCase();
if(_59e.indexOf("rgb")==0){
var _5a0=_59e.match(/rgba*\((\d+), *(\d+), *(\d+)/i);
var ret=_5a0.splice(1,3);
return ret;
}else{
var _5a2=dojo.graphics.color.hex2rgb(_59e);
if(_5a2){
return _5a2;
}else{
return dojo.graphics.color.named[_59e]||[255,255,255];
}
}
};
dojo.graphics.color.hex2rgb=function(hex){
var _5a4="0123456789ABCDEF";
var rgb=new Array(3);
if(hex.indexOf("#")==0){
hex=hex.substring(1);
}
hex=hex.toUpperCase();
if(hex.replace(new RegExp("["+_5a4+"]","g"),"")!=""){
return null;
}
if(hex.length==3){
rgb[0]=hex.charAt(0)+hex.charAt(0);
rgb[1]=hex.charAt(1)+hex.charAt(1);
rgb[2]=hex.charAt(2)+hex.charAt(2);
}else{
rgb[0]=hex.substring(0,2);
rgb[1]=hex.substring(2,4);
rgb[2]=hex.substring(4);
}
for(var i=0;i<rgb.length;i++){
rgb[i]=_5a4.indexOf(rgb[i].charAt(0))*16+_5a4.indexOf(rgb[i].charAt(1));
}
return rgb;
};
dojo.graphics.color.rgb2hex=function(r,g,b){
if(dojo.lang.isArray(r)){
g=r[1]||0;
b=r[2]||0;
r=r[0]||0;
}
var ret=dojo.lang.map([r,g,b],function(x){
x=new Number(x);
var s=x.toString(16);
while(s.length<2){
s="0"+s;
}
return s;
});
ret.unshift("#");
return ret.join("");
};
dojo.provide("dojo.html.color");
dojo.html.getBackgroundColor=function(node){
node=dojo.byId(node);
var _5ae;
do{
_5ae=dojo.html.getStyle(node,"background-color");
if(_5ae.toLowerCase()=="rgba(0, 0, 0, 0)"){
_5ae="transparent";
}
if(node==document.getElementsByTagName("body")[0]){
node=null;
break;
}
node=node.parentNode;
}while(node&&dojo.lang.inArray(["transparent",""],_5ae));
if(_5ae=="transparent"){
_5ae=[255,255,255,0];
}else{
_5ae=dojo.graphics.color.extractRGB(_5ae);
}
return _5ae;
};
dojo.provide("dojo.lfx.html");
dojo.lfx.html._byId=function(_5af){
if(!_5af){
return [];
}
if(dojo.lang.isArrayLike(_5af)){
if(!_5af.alreadyChecked){
var n=[];
dojo.lang.forEach(_5af,function(node){
n.push(dojo.byId(node));
});
n.alreadyChecked=true;
return n;
}else{
return _5af;
}
}else{
var n=[];
n.push(dojo.byId(_5af));
n.alreadyChecked=true;
return n;
}
};
dojo.lfx.html.propertyAnimation=function(_5b2,_5b3,_5b4,_5b5){
_5b2=dojo.lfx.html._byId(_5b2);
if(_5b2.length==1){
dojo.lang.forEach(_5b3,function(prop){
if(typeof prop["start"]=="undefined"){
if(prop.property!="opacity"){
prop.start=parseInt(dojo.html.getComputedStyle(_5b2[0],prop.property));
}else{
prop.start=dojo.html.getOpacity(_5b2[0]);
}
}
});
}
var _5b7=function(_5b8){
var _5b9=new Array(_5b8.length);
for(var i=0;i<_5b8.length;i++){
_5b9[i]=Math.round(_5b8[i]);
}
return _5b9;
};
var _5bb=function(n,_5bd){
n=dojo.byId(n);
if(!n||!n.style){
return;
}
for(var s in _5bd){
if(s=="opacity"){
dojo.html.setOpacity(n,_5bd[s]);
}else{
n.style[s]=_5bd[s];
}
}
};
var _5bf=function(_5c0){
this._properties=_5c0;
this.diffs=new Array(_5c0.length);
dojo.lang.forEach(_5c0,function(prop,i){
if(dojo.lang.isArray(prop.start)){
this.diffs[i]=null;
}else{
if(prop.start instanceof dojo.graphics.color.Color){
prop.startRgb=prop.start.toRgb();
prop.endRgb=prop.end.toRgb();
}else{
this.diffs[i]=prop.end-prop.start;
}
}
},this);
this.getValue=function(n){
var ret={};
dojo.lang.forEach(this._properties,function(prop,i){
var _5c7=null;
if(dojo.lang.isArray(prop.start)){
}else{
if(prop.start instanceof dojo.graphics.color.Color){
_5c7=(prop.units||"rgb")+"(";
for(var j=0;j<prop.startRgb.length;j++){
_5c7+=Math.round(((prop.endRgb[j]-prop.startRgb[j])*n)+prop.startRgb[j])+(j<prop.startRgb.length-1?",":"");
}
_5c7+=")";
}else{
_5c7=((this.diffs[i])*n)+prop.start+(prop.property!="opacity"?prop.units||"px":"");
}
}
ret[dojo.html.toCamelCase(prop.property)]=_5c7;
},this);
return ret;
};
};
var anim=new dojo.lfx.Animation({onAnimate:function(_5ca){
dojo.lang.forEach(_5b2,function(node){
_5bb(node,_5ca);
});
}},_5b4,new _5bf(_5b3),_5b5);
return anim;
};
dojo.lfx.html._makeFadeable=function(_5cc){
var _5cd=function(node){
if(dojo.render.html.ie){
if((node.style.zoom.length==0)&&(dojo.html.getStyle(node,"zoom")=="normal")){
node.style.zoom="1";
}
if((node.style.width.length==0)&&(dojo.html.getStyle(node,"width")=="auto")){
node.style.width="auto";
}
}
};
if(dojo.lang.isArrayLike(_5cc)){
dojo.lang.forEach(_5cc,_5cd);
}else{
_5cd(_5cc);
}
};
dojo.lfx.html.fade=function(_5cf,_5d0,_5d1,_5d2,_5d3){
_5cf=dojo.lfx.html._byId(_5cf);
dojo.lfx.html._makeFadeable(_5cf);
var _5d4={property:"opacity"};
if(typeof _5d0.start!="undefined"){
_5d4.start=_5d0.start;
}else{
_5d4.start=dojo.html.getOpacity(_5cf[0]);
}
if(typeof _5d0.end!="undefined"){
_5d4.end=_5d0.end;
}else{
dojo.raise("dojo.lfx.html.fade needs an end value");
}
var anim=dojo.lfx.propertyAnimation(_5cf,[_5d4],_5d1,_5d2);
if(_5d3){
var _5d6=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_5d6();
_5d3(_5cf,anim);
};
}
return anim;
};
dojo.lfx.html.fadeIn=function(_5d7,_5d8,_5d9,_5da){
return dojo.lfx.html.fade(_5d7,{end:1},_5d8,_5d9,_5da);
};
dojo.lfx.html.fadeOut=function(_5db,_5dc,_5dd,_5de){
return dojo.lfx.html.fade(_5db,{end:0},_5dc,_5dd,_5de);
};
dojo.lfx.html.fadeShow=function(_5df,_5e0,_5e1,_5e2){
_5df=dojo.lfx.html._byId(_5df);
dojo.lang.forEach(_5df,function(node){
dojo.html.setOpacity(node,0);
});
var anim=dojo.lfx.html.fadeIn(_5df,_5e0,_5e1,_5e2);
var _5e5=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_5e5();
if(dojo.lang.isArrayLike(_5df)){
dojo.lang.forEach(_5df,dojo.html.show);
}else{
dojo.html.show(_5df);
}
};
return anim;
};
dojo.lfx.html.fadeHide=function(_5e6,_5e7,_5e8,_5e9){
var anim=dojo.lfx.html.fadeOut(_5e6,_5e7,_5e8,function(){
if(dojo.lang.isArrayLike(_5e6)){
dojo.lang.forEach(_5e6,dojo.html.hide);
}else{
dojo.html.hide(_5e6);
}
if(_5e9){
_5e9(_5e6,anim);
}
});
return anim;
};
dojo.lfx.html.wipeIn=function(_5eb,_5ec,_5ed,_5ee){
_5eb=dojo.lfx.html._byId(_5eb);
var _5ef=[];
dojo.lang.forEach(_5eb,function(node){
var _5f1=dojo.html.getStyle(node,"overflow");
if(_5f1=="visible"){
node.style.overflow="hidden";
}
node.style.height="0px";
dojo.html.show(node);
var anim=dojo.lfx.propertyAnimation(node,[{property:"height",start:0,end:node.scrollHeight}],_5ec,_5ed);
var _5f3=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_5f3();
node.style.overflow=_5f1;
node.style.height="auto";
if(_5ee){
_5ee(node,anim);
}
};
_5ef.push(anim);
});
if(_5eb.length>1){
return dojo.lfx.combine(_5ef);
}else{
return _5ef[0];
}
};
dojo.lfx.html.wipeOut=function(_5f4,_5f5,_5f6,_5f7){
_5f4=dojo.lfx.html._byId(_5f4);
var _5f8=[];
dojo.lang.forEach(_5f4,function(node){
var _5fa=dojo.html.getStyle(node,"overflow");
if(_5fa=="visible"){
node.style.overflow="hidden";
}
dojo.html.show(node);
var anim=dojo.lfx.propertyAnimation(node,[{property:"height",start:dojo.html.getContentBox(node).height,end:0}],_5f5,_5f6);
var _5fc=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_5fc();
dojo.html.hide(node);
node.style.overflow=_5fa;
if(_5f7){
_5f7(node,anim);
}
};
_5f8.push(anim);
});
if(_5f4.length>1){
return dojo.lfx.combine(_5f8);
}else{
return _5f8[0];
}
};
dojo.lfx.html.slideTo=function(_5fd,_5fe,_5ff,_600,_601){
_5fd=dojo.lfx.html._byId(_5fd);
var _602=[];
if(dojo.lang.isArray(_5fe)){
dojo.deprecated("dojo.lfx.html.slideTo(node, array)","use dojo.lfx.html.slideTo(node, {top: value, left: value});","0.5");
_5fe={top:_5fe[0],left:_5fe[1]};
}
dojo.lang.forEach(_5fd,function(node){
var top=null;
var left=null;
var init=(function(){
var _607=node;
return function(){
var pos=dojo.html.getComputedStyle(_607,"position");
top=(pos=="absolute"?node.offsetTop:parseInt(dojo.html.getComputedStyle(node,"top"))||0);
left=(pos=="absolute"?node.offsetLeft:parseInt(dojo.html.getComputedStyle(node,"left"))||0);
if(!dojo.lang.inArray(["absolute","relative"],pos)){
var ret=dojo.html.abs(_607,true);
dojo.html.setStyleAttributes(_607,"position:absolute;top:"+ret.y+"px;left:"+ret.x+"px;");
top=ret.y;
left=ret.x;
}
};
})();
init();
var anim=dojo.lfx.propertyAnimation(node,[{property:"top",start:top,end:_5fe.top||0},{property:"left",start:left,end:_5fe.left||0}],_5ff,_600);
var _60b=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_60b();
init();
};
if(_601){
var _60c=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_60c();
_601(_5fd,anim);
};
}
_602.push(anim);
});
if(_5fd.length>1){
return dojo.lfx.combine(_602);
}else{
return _602[0];
}
};
dojo.lfx.html.slideBy=function(_60d,_60e,_60f,_610,_611){
_60d=dojo.lfx.html._byId(_60d);
var _612=[];
if(dojo.lang.isArray(_60e)){
dojo.deprecated("dojo.lfx.html.slideBy(node, array)","use dojo.lfx.html.slideBy(node, {top: value, left: value});","0.5");
_60e={top:_60e[0],left:_60e[1]};
}
dojo.lang.forEach(_60d,function(node){
var top=null;
var left=null;
var init=(function(){
var _617=node;
return function(){
var pos=dojo.html.getComputedStyle(_617,"position");
top=(pos=="absolute"?node.offsetTop:parseInt(dojo.html.getComputedStyle(node,"top"))||0);
left=(pos=="absolute"?node.offsetLeft:parseInt(dojo.html.getComputedStyle(node,"left"))||0);
if(!dojo.lang.inArray(["absolute","relative"],pos)){
var ret=dojo.html.abs(_617,true);
dojo.html.setStyleAttributes(_617,"position:absolute;top:"+ret.y+"px;left:"+ret.x+"px;");
top=ret.y;
left=ret.x;
}
};
})();
init();
var anim=dojo.lfx.propertyAnimation(node,[{property:"top",start:top,end:top+(_60e.top||0)},{property:"left",start:left,end:left+(_60e.left||0)}],_60f,_610);
var _61b=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_61b();
init();
};
if(_611){
var _61c=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_61c();
_611(_60d,anim);
};
}
_612.push(anim);
});
if(_60d.length>1){
return dojo.lfx.combine(_612);
}else{
return _612[0];
}
};
dojo.lfx.html.explode=function(_61d,_61e,_61f,_620,_621){
_61d=dojo.byId(_61d);
_61e=dojo.byId(_61e);
var _622=dojo.html.toCoordinateObject(_61d,true);
var _623=document.createElement("div");
dojo.html.copyStyle(_623,_61e);
with(_623.style){
position="absolute";
display="none";
}
dojo.body().appendChild(_623);
with(_61e.style){
visibility="hidden";
display="block";
}
var _624=dojo.html.toCoordinateObject(_61e,true);
with(_61e.style){
display="none";
visibility="visible";
}
var anim=new dojo.lfx.propertyAnimation(_623,[{property:"height",start:_622.height,end:_624.height},{property:"width",start:_622.width,end:_624.width},{property:"top",start:_622.top,end:_624.top},{property:"left",start:_622.left,end:_624.left},{property:"opacity",start:0.3,end:1}],_61f,_620);
anim.beforeBegin=function(){
dojo.html.setDisplay(_623,"block");
};
anim.onEnd=function(){
dojo.html.setDisplay(_61e,"block");
_623.parentNode.removeChild(_623);
};
if(_621){
var _626=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_626();
_621(_61e,anim);
};
}
return anim;
};
dojo.lfx.html.implode=function(_627,end,_629,_62a,_62b){
_627=dojo.byId(_627);
end=dojo.byId(end);
var _62c=dojo.html.toCoordinateObject(_627,true);
var _62d=dojo.html.toCoordinateObject(end,true);
var _62e=document.createElement("div");
dojo.html.copyStyle(_62e,_627);
dojo.html.setOpacity(_62e,0.3);
with(_62e.style){
position="absolute";
display="none";
}
dojo.body().appendChild(_62e);
var anim=new dojo.lfx.propertyAnimation(_62e,[{property:"height",start:_62c.height,end:_62d.height},{property:"width",start:_62c.width,end:_62d.width},{property:"top",start:_62c.top,end:_62d.top},{property:"left",start:_62c.left,end:_62d.left},{property:"opacity",start:1,end:0.3}],_629,_62a);
anim.beforeBegin=function(){
dojo.html.hide(_627);
dojo.html.show(_62e);
};
anim.onEnd=function(){
_62e.parentNode.removeChild(_62e);
};
if(_62b){
var _630=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_630();
_62b(_627,anim);
};
}
return anim;
};
dojo.lfx.html.highlight=function(_631,_632,_633,_634,_635){
_631=dojo.lfx.html._byId(_631);
var _636=[];
dojo.lang.forEach(_631,function(node){
var _638=dojo.html.getBackgroundColor(node);
var bg=dojo.html.getStyle(node,"background-color").toLowerCase();
var _63a=dojo.html.getStyle(node,"background-image");
var _63b=(bg=="transparent"||bg=="rgba(0, 0, 0, 0)");
while(_638.length>3){
_638.pop();
}
var rgb=new dojo.graphics.color.Color(_632);
var _63d=new dojo.graphics.color.Color(_638);
var anim=dojo.lfx.propertyAnimation(node,[{property:"background-color",start:rgb,end:_63d}],_633,_634);
var _63f=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_63f();
if(_63a){
node.style.backgroundImage="none";
}
node.style.backgroundColor="rgb("+rgb.toRgb().join(",")+")";
};
var _640=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_640();
if(_63a){
node.style.backgroundImage=_63a;
}
if(_63b){
node.style.backgroundColor="transparent";
}
if(_635){
_635(node,anim);
}
};
_636.push(anim);
});
if(_631.length>1){
return dojo.lfx.combine(_636);
}else{
return _636[0];
}
};
dojo.lfx.html.unhighlight=function(_641,_642,_643,_644,_645){
_641=dojo.lfx.html._byId(_641);
var _646=[];
dojo.lang.forEach(_641,function(node){
var _648=new dojo.graphics.color.Color(dojo.html.getBackgroundColor(node));
var rgb=new dojo.graphics.color.Color(_642);
var _64a=dojo.html.getStyle(node,"background-image");
var anim=dojo.lfx.propertyAnimation(node,[{property:"background-color",start:_648,end:rgb}],_643,_644);
var _64c=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_64c();
if(_64a){
node.style.backgroundImage="none";
}
node.style.backgroundColor="rgb("+_648.toRgb().join(",")+")";
};
var _64d=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_64d();
if(_645){
_645(node,anim);
}
};
_646.push(anim);
});
if(_641.length>1){
return dojo.lfx.combine(_646);
}else{
return _646[0];
}
};
dojo.lang.mixin(dojo.lfx,dojo.lfx.html);
dojo.provide("dojo.lfx.*");
dojo.provide("dojo.lfx.toggle");
dojo.lfx.toggle.plain={show:function(node,_64f,_650,_651){
dojo.html.show(node);
if(dojo.lang.isFunction(_651)){
_651();
}
},hide:function(node,_653,_654,_655){
dojo.html.hide(node);
if(dojo.lang.isFunction(_655)){
_655();
}
}};
dojo.lfx.toggle.fade={show:function(node,_657,_658,_659){
dojo.lfx.fadeShow(node,_657,_658,_659).play();
},hide:function(node,_65b,_65c,_65d){
dojo.lfx.fadeHide(node,_65b,_65c,_65d).play();
}};
dojo.lfx.toggle.wipe={show:function(node,_65f,_660,_661){
dojo.lfx.wipeIn(node,_65f,_660,_661).play();
},hide:function(node,_663,_664,_665){
dojo.lfx.wipeOut(node,_663,_664,_665).play();
}};
dojo.lfx.toggle.explode={show:function(node,_667,_668,_669,_66a){
dojo.lfx.explode(_66a||{x:0,y:0,width:0,height:0},node,_667,_668,_669).play();
},hide:function(node,_66c,_66d,_66e,_66f){
dojo.lfx.implode(node,_66f||{x:0,y:0,width:0,height:0},_66c,_66d,_66e).play();
}};
dojo.provide("dojo.widget.HtmlWidget");
dojo.declare("dojo.widget.HtmlWidget",dojo.widget.DomWidget,{widgetType:"HtmlWidget",templateCssPath:null,templatePath:null,toggle:"plain",toggleDuration:150,animationInProgress:false,initialize:function(args,frag){
},postMixInProperties:function(args,frag){
this.toggleObj=dojo.lfx.toggle[this.toggle.toLowerCase()]||dojo.lfx.toggle.plain;
},getContainerHeight:function(){
dojo.unimplemented("dojo.widget.HtmlWidget.getContainerHeight");
},getContainerWidth:function(){
return this.parent.domNode.offsetWidth;
},setNativeHeight:function(_674){
var ch=this.getContainerHeight();
},createNodesFromText:function(txt,wrap){
return dojo.html.createNodesFromText(txt,wrap);
},destroyRendering:function(_678){
try{
if(!_678&&this.domNode){
dojo.event.browser.clean(this.domNode);
}
this.domNode.parentNode.removeChild(this.domNode);
delete this.domNode;
}
catch(e){
}
},isShowing:function(){
return dojo.html.isShowing(this.domNode);
},toggleShowing:function(){
if(this.isHidden){
this.show();
}else{
this.hide();
}
},show:function(){
this.animationInProgress=true;
this.isHidden=false;
this.toggleObj.show(this.domNode,this.toggleDuration,null,dojo.lang.hitch(this,this.onShow),this.explodeSrc);
},onShow:function(){
this.animationInProgress=false;
this.checkSize();
},hide:function(){
this.animationInProgress=true;
this.isHidden=true;
this.toggleObj.hide(this.domNode,this.toggleDuration,null,dojo.lang.hitch(this,this.onHide),this.explodeSrc);
},onHide:function(){
this.animationInProgress=false;
},_isResized:function(w,h){
if(!this.isShowing()){
return false;
}
var wh=dojo.html.getMarginBox(this.domNode);
var _67c=w||wh.width;
var _67d=h||wh.height;
if(this.width==_67c&&this.height==_67d){
return false;
}
this.width=_67c;
this.height=_67d;
return true;
},checkSize:function(){
if(!this._isResized()){
return;
}
this.onResized();
},resizeTo:function(w,h){
if(!this._isResized(w,h)){
return;
}
dojo.html.setMarginBox(this.domNode,{width:w,height:h});
this.onResized();
},resizeSoon:function(){
if(this.isShowing()){
dojo.lang.setTimeout(this,this.onResized,0);
}
},onResized:function(){
dojo.lang.forEach(this.children,function(_680){
if(_680["checkSize"]){
_680.checkSize();
}
});
}});
dojo.provide("dojo.widget.*");
dojo.provide("dojo.string.common");
dojo.string.trim=function(str,wh){
if(!str.replace){
return str;
}
if(!str.length){
return str;
}
var re=(wh>0)?(/^\s+/):(wh<0)?(/\s+$/):(/^\s+|\s+$/g);
return str.replace(re,"");
};
dojo.string.trimStart=function(str){
return dojo.string.trim(str,1);
};
dojo.string.trimEnd=function(str){
return dojo.string.trim(str,-1);
};
dojo.string.repeat=function(str,_687,_688){
var out="";
for(var i=0;i<_687;i++){
out+=str;
if(_688&&i<_687-1){
out+=_688;
}
}
return out;
};
dojo.string.pad=function(str,len,c,dir){
var out=String(str);
if(!c){
c="0";
}
if(!dir){
dir=1;
}
while(out.length<len){
if(dir>0){
out=c+out;
}else{
out+=c;
}
}
return out;
};
dojo.string.padLeft=function(str,len,c){
return dojo.string.pad(str,len,c,1);
};
dojo.string.padRight=function(str,len,c){
return dojo.string.pad(str,len,c,-1);
};
dojo.provide("dojo.string");
dojo.provide("dojo.io.IO");
dojo.io.transports=[];
dojo.io.hdlrFuncNames=["load","error","timeout"];
dojo.io.Request=function(url,_697,_698,_699){
if((arguments.length==1)&&(arguments[0].constructor==Object)){
this.fromKwArgs(arguments[0]);
}else{
this.url=url;
if(_697){
this.mimetype=_697;
}
if(_698){
this.transport=_698;
}
if(arguments.length>=4){
this.changeUrl=_699;
}
}
};
dojo.lang.extend(dojo.io.Request,{url:"",mimetype:"text/plain",method:"GET",content:undefined,transport:undefined,changeUrl:undefined,formNode:undefined,sync:false,bindSuccess:false,useCache:false,preventCache:false,load:function(type,data,evt){
},error:function(type,_69e){
},timeout:function(type){
},handle:function(){
},timeoutSeconds:0,abort:function(){
},fromKwArgs:function(_6a0){
if(_6a0["url"]){
_6a0.url=_6a0.url.toString();
}
if(_6a0["formNode"]){
_6a0.formNode=dojo.byId(_6a0.formNode);
}
if(!_6a0["method"]&&_6a0["formNode"]&&_6a0["formNode"].method){
_6a0.method=_6a0["formNode"].method;
}
if(!_6a0["handle"]&&_6a0["handler"]){
_6a0.handle=_6a0.handler;
}
if(!_6a0["load"]&&_6a0["loaded"]){
_6a0.load=_6a0.loaded;
}
if(!_6a0["changeUrl"]&&_6a0["changeURL"]){
_6a0.changeUrl=_6a0.changeURL;
}
_6a0.encoding=dojo.lang.firstValued(_6a0["encoding"],djConfig["bindEncoding"],"");
_6a0.sendTransport=dojo.lang.firstValued(_6a0["sendTransport"],djConfig["ioSendTransport"],false);
var _6a1=dojo.lang.isFunction;
for(var x=0;x<dojo.io.hdlrFuncNames.length;x++){
var fn=dojo.io.hdlrFuncNames[x];
if(_6a0[fn]&&_6a1(_6a0[fn])){
continue;
}
if(_6a0["handle"]&&_6a1(_6a0["handle"])){
_6a0[fn]=_6a0.handle;
}
}
dojo.lang.mixin(this,_6a0);
}});
dojo.io.Error=function(msg,type,num){
this.message=msg;
this.type=type||"unknown";
this.number=num||0;
};
dojo.io.transports.addTransport=function(name){
this.push(name);
this[name]=dojo.io[name];
};
dojo.io.bind=function(_6a8){
if(!(_6a8 instanceof dojo.io.Request)){
try{
_6a8=new dojo.io.Request(_6a8);
}
catch(e){
dojo.debug(e);
}
}
var _6a9="";
if(_6a8["transport"]){
_6a9=_6a8["transport"];
if(!this[_6a9]){
return _6a8;
}
}else{
for(var x=0;x<dojo.io.transports.length;x++){
var tmp=dojo.io.transports[x];
if((this[tmp])&&(this[tmp].canHandle(_6a8))){
_6a9=tmp;
}
}
if(_6a9==""){
return _6a8;
}
}
this[_6a9].bind(_6a8);
_6a8.bindSuccess=true;
return _6a8;
};
dojo.io.queueBind=function(_6ac){
if(!(_6ac instanceof dojo.io.Request)){
try{
_6ac=new dojo.io.Request(_6ac);
}
catch(e){
dojo.debug(e);
}
}
var _6ad=_6ac.load;
_6ac.load=function(){
dojo.io._queueBindInFlight=false;
var ret=_6ad.apply(this,arguments);
dojo.io._dispatchNextQueueBind();
return ret;
};
var _6af=_6ac.error;
_6ac.error=function(){
dojo.io._queueBindInFlight=false;
var ret=_6af.apply(this,arguments);
dojo.io._dispatchNextQueueBind();
return ret;
};
dojo.io._bindQueue.push(_6ac);
dojo.io._dispatchNextQueueBind();
return _6ac;
};
dojo.io._dispatchNextQueueBind=function(){
if(!dojo.io._queueBindInFlight){
dojo.io._queueBindInFlight=true;
if(dojo.io._bindQueue.length>0){
dojo.io.bind(dojo.io._bindQueue.shift());
}else{
dojo.io._queueBindInFlight=false;
}
}
};
dojo.io._bindQueue=[];
dojo.io._queueBindInFlight=false;
dojo.io.argsFromMap=function(map,_6b2,last){
var enc=/utf/i.test(_6b2||"")?encodeURIComponent:dojo.string.encodeAscii;
var _6b5=[];
var _6b6=new Object();
for(var name in map){
var _6b8=function(elt){
var val=enc(name)+"="+enc(elt);
_6b5[(last==name)?"push":"unshift"](val);
};
if(!_6b6[name]){
var _6bb=map[name];
if(dojo.lang.isArray(_6bb)){
dojo.lang.forEach(_6bb,_6b8);
}else{
_6b8(_6bb);
}
}
}
return _6b5.join("&");
};
dojo.io.setIFrameSrc=function(_6bc,src,_6be){
try{
var r=dojo.render.html;
if(!_6be){
if(r.safari){
_6bc.location=src;
}else{
frames[_6bc.name].location=src;
}
}else{
var idoc;
if(r.ie){
idoc=_6bc.contentWindow.document;
}else{
if(r.safari){
idoc=_6bc.document;
}else{
idoc=_6bc.contentWindow;
}
}
if(!idoc){
_6bc.location=src;
return;
}else{
idoc.location.replace(src);
}
}
}
catch(e){
dojo.debug(e);
dojo.debug("setIFrameSrc: "+e);
}
};
dojo.provide("dojo.string.extras");
dojo.string.substituteParams=function(_6c1,hash){
var map=(typeof hash=="object")?hash:dojo.lang.toArray(arguments,1);
return _6c1.replace(/\%\{(\w+)\}/g,function(_6c4,key){
return map[key]||dojo.raise("Substitution not found: "+key);
});
};
dojo.string.capitalize=function(str){
if(!dojo.lang.isString(str)){
return "";
}
if(arguments.length==0){
str=this;
}
var _6c7=str.split(" ");
for(var i=0;i<_6c7.length;i++){
_6c7[i]=_6c7[i].charAt(0).toUpperCase()+_6c7[i].substring(1);
}
return _6c7.join(" ");
};
dojo.string.isBlank=function(str){
if(!dojo.lang.isString(str)){
return true;
}
return (dojo.string.trim(str).length==0);
};
dojo.string.encodeAscii=function(str){
if(!dojo.lang.isString(str)){
return str;
}
var ret="";
var _6cc=escape(str);
var _6cd,re=/%u([0-9A-F]{4})/i;
while((_6cd=_6cc.match(re))){
var num=Number("0x"+_6cd[1]);
var _6cf=escape("&#"+num+";");
ret+=_6cc.substring(0,_6cd.index)+_6cf;
_6cc=_6cc.substring(_6cd.index+_6cd[0].length);
}
ret+=_6cc.replace(/\+/g,"%2B");
return ret;
};
dojo.string.escape=function(type,str){
var args=dojo.lang.toArray(arguments,1);
switch(type.toLowerCase()){
case "xml":
case "html":
case "xhtml":
return dojo.string.escapeXml.apply(this,args);
case "sql":
return dojo.string.escapeSql.apply(this,args);
case "regexp":
case "regex":
return dojo.string.escapeRegExp.apply(this,args);
case "javascript":
case "jscript":
case "js":
return dojo.string.escapeJavaScript.apply(this,args);
case "ascii":
return dojo.string.encodeAscii.apply(this,args);
default:
return str;
}
};
dojo.string.escapeXml=function(str,_6d4){
str=str.replace(/&/gm,"&amp;").replace(/</gm,"&lt;").replace(/>/gm,"&gt;").replace(/"/gm,"&quot;");
if(!_6d4){
str=str.replace(/'/gm,"&#39;");
}
return str;
};
dojo.string.escapeSql=function(str){
return str.replace(/'/gm,"''");
};
dojo.string.escapeRegExp=function(str){
return str.replace(/\\/gm,"\\\\").replace(/([\f\b\n\t\r[\^$|?*+(){}])/gm,"\\$1");
};
dojo.string.escapeJavaScript=function(str){
return str.replace(/(["'\f\b\n\t\r])/gm,"\\$1");
};
dojo.string.escapeString=function(str){
return ("\""+str.replace(/(["\\])/g,"\\$1")+"\"").replace(/[\f]/g,"\\f").replace(/[\b]/g,"\\b").replace(/[\n]/g,"\\n").replace(/[\t]/g,"\\t").replace(/[\r]/g,"\\r");
};
dojo.string.summary=function(str,len){
if(!len||str.length<=len){
return str;
}else{
return str.substring(0,len).replace(/\.+$/,"")+"...";
}
};
dojo.string.endsWith=function(str,end,_6dd){
if(_6dd){
str=str.toLowerCase();
end=end.toLowerCase();
}
if((str.length-end.length)<0){
return false;
}
return str.lastIndexOf(end)==str.length-end.length;
};
dojo.string.endsWithAny=function(str){
for(var i=1;i<arguments.length;i++){
if(dojo.string.endsWith(str,arguments[i])){
return true;
}
}
return false;
};
dojo.string.startsWith=function(str,_6e1,_6e2){
if(_6e2){
str=str.toLowerCase();
_6e1=_6e1.toLowerCase();
}
return str.indexOf(_6e1)==0;
};
dojo.string.startsWithAny=function(str){
for(var i=1;i<arguments.length;i++){
if(dojo.string.startsWith(str,arguments[i])){
return true;
}
}
return false;
};
dojo.string.has=function(str){
for(var i=1;i<arguments.length;i++){
if(str.indexOf(arguments[i])>-1){
return true;
}
}
return false;
};
dojo.string.normalizeNewlines=function(text,_6e8){
if(_6e8=="\n"){
text=text.replace(/\r\n/g,"\n");
text=text.replace(/\r/g,"\n");
}else{
if(_6e8=="\r"){
text=text.replace(/\r\n/g,"\r");
text=text.replace(/\n/g,"\r");
}else{
text=text.replace(/([^\r])\n/g,"$1\r\n");
text=text.replace(/\r([^\n])/g,"\r\n$1");
}
}
return text;
};
dojo.string.splitEscaped=function(str,_6ea){
var _6eb=[];
for(var i=0,prevcomma=0;i<str.length;i++){
if(str.charAt(i)=="\\"){
i++;
continue;
}
if(str.charAt(i)==_6ea){
_6eb.push(str.substring(prevcomma,i));
prevcomma=i+1;
}
}
_6eb.push(str.substr(prevcomma));
return _6eb;
};
dojo.provide("dojo.undo.browser");
try{
if((!djConfig["preventBackButtonFix"])&&(!dojo.hostenv.post_load_)){
document.write("<iframe style='border: 0px; width: 1px; height: 1px; position: absolute; bottom: 0px; right: 0px; visibility: visible;' name='djhistory' id='djhistory' src='"+(dojo.hostenv.getBaseScriptUri()+"iframe_history.html")+"'></iframe>");
}
}
catch(e){
}
if(dojo.render.html.opera){
dojo.debug("Opera is not supported with dojo.undo.browser, so back/forward detection will not work.");
}
dojo.undo.browser={initialHref:window.location.href,initialHash:window.location.hash,moveForward:false,historyStack:[],forwardStack:[],historyIframe:null,bookmarkAnchor:null,locationTimer:null,setInitialState:function(args){
this.initialState={"url":this.initialHref,"kwArgs":args,"urlHash":this.initialHash};
},addToHistory:function(args){
var hash=null;
if(!this.historyIframe){
this.historyIframe=window.frames["djhistory"];
}
if(!this.bookmarkAnchor){
this.bookmarkAnchor=document.createElement("a");
dojo.body().appendChild(this.bookmarkAnchor);
this.bookmarkAnchor.style.display="none";
}
if((!args["changeUrl"])||(dojo.render.html.ie)){
var url=dojo.hostenv.getBaseScriptUri()+"iframe_history.html?"+(new Date()).getTime();
this.moveForward=true;
dojo.io.setIFrameSrc(this.historyIframe,url,false);
}
if(args["changeUrl"]){
this.changingUrl=true;
hash="#"+((args["changeUrl"]!==true)?args["changeUrl"]:(new Date()).getTime());
setTimeout("window.location.href = '"+hash+"'; dojo.undo.browser.changingUrl = false;",1);
this.bookmarkAnchor.href=hash;
if(dojo.render.html.ie){
var _6f1=args["back"]||args["backButton"]||args["handle"];
var tcb=function(_6f3){
if(window.location.hash!=""){
setTimeout("window.location.href = '"+hash+"';",1);
}
_6f1.apply(this,[_6f3]);
};
if(args["back"]){
args.back=tcb;
}else{
if(args["backButton"]){
args.backButton=tcb;
}else{
if(args["handle"]){
args.handle=tcb;
}
}
}
this.forwardStack=[];
var _6f4=args["forward"]||args["forwardButton"]||args["handle"];
var tfw=function(_6f6){
if(window.location.hash!=""){
window.location.href=hash;
}
if(_6f4){
_6f4.apply(this,[_6f6]);
}
};
if(args["forward"]){
args.forward=tfw;
}else{
if(args["forwardButton"]){
args.forwardButton=tfw;
}else{
if(args["handle"]){
args.handle=tfw;
}
}
}
}else{
if(dojo.render.html.moz){
if(!this.locationTimer){
this.locationTimer=setInterval("dojo.undo.browser.checkLocation();",200);
}
}
}
}
this.historyStack.push({"url":url,"kwArgs":args,"urlHash":hash});
},checkLocation:function(){
if(!this.changingUrl){
var hsl=this.historyStack.length;
if((window.location.hash==this.initialHash||window.location.href==this.initialHref)&&(hsl==1)){
this.handleBackButton();
return;
}
if(this.forwardStack.length>0){
if(this.forwardStack[this.forwardStack.length-1].urlHash==window.location.hash){
this.handleForwardButton();
return;
}
}
if((hsl>=2)&&(this.historyStack[hsl-2])){
if(this.historyStack[hsl-2].urlHash==window.location.hash){
this.handleBackButton();
return;
}
}
}
},iframeLoaded:function(evt,_6f9){
if(!dojo.render.html.opera){
var _6fa=this._getUrlQuery(_6f9.href);
if(_6fa==null){
if(this.historyStack.length==1){
this.handleBackButton();
}
return;
}
if(this.moveForward){
this.moveForward=false;
return;
}
if(this.historyStack.length>=2&&_6fa==this._getUrlQuery(this.historyStack[this.historyStack.length-2].url)){
this.handleBackButton();
}else{
if(this.forwardStack.length>0&&_6fa==this._getUrlQuery(this.forwardStack[this.forwardStack.length-1].url)){
this.handleForwardButton();
}
}
}
},handleBackButton:function(){
var _6fb=this.historyStack.pop();
if(!_6fb){
return;
}
var last=this.historyStack[this.historyStack.length-1];
if(!last&&this.historyStack.length==0){
last=this.initialState;
}
if(last){
if(last.kwArgs["back"]){
last.kwArgs["back"]();
}else{
if(last.kwArgs["backButton"]){
last.kwArgs["backButton"]();
}else{
if(last.kwArgs["handle"]){
last.kwArgs.handle("back");
}
}
}
}
this.forwardStack.push(_6fb);
},handleForwardButton:function(){
var last=this.forwardStack.pop();
if(!last){
return;
}
if(last.kwArgs["forward"]){
last.kwArgs.forward();
}else{
if(last.kwArgs["forwardButton"]){
last.kwArgs.forwardButton();
}else{
if(last.kwArgs["handle"]){
last.kwArgs.handle("forward");
}
}
}
this.historyStack.push(last);
},_getUrlQuery:function(url){
var _6ff=url.split("?");
if(_6ff.length<2){
return null;
}else{
return _6ff[1];
}
}};
dojo.provide("dojo.io.BrowserIO");
dojo.io.checkChildrenForFile=function(node){
var _701=false;
var _702=node.getElementsByTagName("input");
dojo.lang.forEach(_702,function(_703){
if(_701){
return;
}
if(_703.getAttribute("type")=="file"){
_701=true;
}
});
return _701;
};
dojo.io.formHasFile=function(_704){
return dojo.io.checkChildrenForFile(_704);
};
dojo.io.updateNode=function(node,_706){
node=dojo.byId(node);
var args=_706;
if(dojo.lang.isString(_706)){
args={url:_706};
}
args.mimetype="text/html";
args.load=function(t,d,e){
while(node.firstChild){
if(dojo["event"]){
try{
dojo.event.browser.clean(node.firstChild);
}
catch(e){
}
}
node.removeChild(node.firstChild);
}
node.innerHTML=d;
};
dojo.io.bind(args);
};
dojo.io.formFilter=function(node){
var type=(node.type||"").toLowerCase();
return !node.disabled&&node.name&&!dojo.lang.inArray(["file","submit","image","reset","button"],type);
};
dojo.io.encodeForm=function(_70d,_70e,_70f){
if((!_70d)||(!_70d.tagName)||(!_70d.tagName.toLowerCase()=="form")){
dojo.raise("Attempted to encode a non-form element.");
}
if(!_70f){
_70f=dojo.io.formFilter;
}
var enc=/utf/i.test(_70e||"")?encodeURIComponent:dojo.string.encodeAscii;
var _711=[];
for(var i=0;i<_70d.elements.length;i++){
var elm=_70d.elements[i];
if(!elm||elm.tagName.toLowerCase()=="fieldset"||!_70f(elm)){
continue;
}
var name=enc(elm.name);
var type=elm.type.toLowerCase();
if(type=="select-multiple"){
for(var j=0;j<elm.options.length;j++){
if(elm.options[j].selected){
_711.push(name+"="+enc(elm.options[j].value));
}
}
}else{
if(dojo.lang.inArray(["radio","checkbox"],type)){
if(elm.checked){
_711.push(name+"="+enc(elm.value));
}
}else{
_711.push(name+"="+enc(elm.value));
}
}
}
var _717=_70d.getElementsByTagName("input");
for(var i=0;i<_717.length;i++){
var _718=_717[i];
if(_718.type.toLowerCase()=="image"&&_718.form==_70d&&_70f(_718)){
var name=enc(_718.name);
_711.push(name+"="+enc(_718.value));
_711.push(name+".x=0");
_711.push(name+".y=0");
}
}
return _711.join("&")+"&";
};
dojo.io.FormBind=function(args){
this.bindArgs={};
if(args&&args.formNode){
this.init(args);
}else{
if(args){
this.init({formNode:args});
}
}
};
dojo.lang.extend(dojo.io.FormBind,{form:null,bindArgs:null,clickedButton:null,init:function(args){
var form=dojo.byId(args.formNode);
if(!form||!form.tagName||form.tagName.toLowerCase()!="form"){
throw new Error("FormBind: Couldn't apply, invalid form");
}else{
if(this.form==form){
return;
}else{
if(this.form){
throw new Error("FormBind: Already applied to a form");
}
}
}
dojo.lang.mixin(this.bindArgs,args);
this.form=form;
this.connect(form,"onsubmit","submit");
for(var i=0;i<form.elements.length;i++){
var node=form.elements[i];
if(node&&node.type&&dojo.lang.inArray(["submit","button"],node.type.toLowerCase())){
this.connect(node,"onclick","click");
}
}
var _71e=form.getElementsByTagName("input");
for(var i=0;i<_71e.length;i++){
var _71f=_71e[i];
if(_71f.type.toLowerCase()=="image"&&_71f.form==form){
this.connect(_71f,"onclick","click");
}
}
},onSubmit:function(form){
return true;
},submit:function(e){
e.preventDefault();
if(this.onSubmit(this.form)){
dojo.io.bind(dojo.lang.mixin(this.bindArgs,{formFilter:dojo.lang.hitch(this,"formFilter")}));
}
},click:function(e){
var node=e.currentTarget;
if(node.disabled){
return;
}
this.clickedButton=node;
},formFilter:function(node){
var type=(node.type||"").toLowerCase();
var _726=false;
if(node.disabled||!node.name){
_726=false;
}else{
if(dojo.lang.inArray(["submit","button","image"],type)){
if(!this.clickedButton){
this.clickedButton=node;
}
_726=node==this.clickedButton;
}else{
_726=!dojo.lang.inArray(["file","submit","reset","button"],type);
}
}
return _726;
},connect:function(_727,_728,_729){
if(dojo.evalObjPath("dojo.event.connect")){
dojo.event.connect(_727,_728,this,_729);
}else{
var fcn=dojo.lang.hitch(this,_729);
_727[_728]=function(e){
if(!e){
e=window.event;
}
if(!e.currentTarget){
e.currentTarget=e.srcElement;
}
if(!e.preventDefault){
e.preventDefault=function(){
window.event.returnValue=false;
};
}
fcn(e);
};
}
}});
dojo.io.XMLHTTPTransport=new function(){
var _72c=this;
var _72d={};
this.useCache=false;
this.preventCache=false;
function getCacheKey(url,_72f,_730){
return url+"|"+_72f+"|"+_730.toLowerCase();
}
function addToCache(url,_732,_733,http){
_72d[getCacheKey(url,_732,_733)]=http;
}
function getFromCache(url,_736,_737){
return _72d[getCacheKey(url,_736,_737)];
}
this.clearCache=function(){
_72d={};
};
function doLoad(_738,http,url,_73b,_73c){
if(((http.status>=200)&&(http.status<300))||(http.status==304)||(location.protocol=="file:"&&(http.status==0||http.status==undefined))||(location.protocol=="chrome:"&&(http.status==0||http.status==undefined))){
var ret;
if(_738.method.toLowerCase()=="head"){
var _73e=http.getAllResponseHeaders();
ret={};
ret.toString=function(){
return _73e;
};
var _73f=_73e.split(/[\r\n]+/g);
for(var i=0;i<_73f.length;i++){
var pair=_73f[i].match(/^([^:]+)\s*:\s*(.+)$/i);
if(pair){
ret[pair[1]]=pair[2];
}
}
}else{
if(_738.mimetype=="text/javascript"){
try{
ret=dj_eval(http.responseText);
}
catch(e){
dojo.debug(e);
dojo.debug(http.responseText);
ret=null;
}
}else{
if(_738.mimetype=="text/json"){
try{
ret=dj_eval("("+http.responseText+")");
}
catch(e){
dojo.debug(e);
dojo.debug(http.responseText);
ret=false;
}
}else{
if((_738.mimetype=="application/xml")||(_738.mimetype=="text/xml")){
ret=http.responseXML;
if(!ret||typeof ret=="string"||!http.getResponseHeader("Content-Type")){
ret=dojo.dom.createDocumentFromText(http.responseText);
}
}else{
ret=http.responseText;
}
}
}
}
if(_73c){
addToCache(url,_73b,_738.method,http);
}
_738[(typeof _738.load=="function")?"load":"handle"]("load",ret,http,_738);
}else{
var _742=new dojo.io.Error("XMLHttpTransport Error: "+http.status+" "+http.statusText);
_738[(typeof _738.error=="function")?"error":"handle"]("error",_742,http,_738);
}
}
function setHeaders(http,_744){
if(_744["headers"]){
for(var _745 in _744["headers"]){
if(_745.toLowerCase()=="content-type"&&!_744["contentType"]){
_744["contentType"]=_744["headers"][_745];
}else{
http.setRequestHeader(_745,_744["headers"][_745]);
}
}
}
}
this.inFlight=[];
this.inFlightTimer=null;
this.startWatchingInFlight=function(){
if(!this.inFlightTimer){
this.inFlightTimer=setTimeout("dojo.io.XMLHTTPTransport.watchInFlight();",10);
}
};
this.watchInFlight=function(){
var now=null;
if(!dojo.hostenv._blockAsync&&!_72c._blockAsync){
for(var x=this.inFlight.length-1;x>=0;x--){
var tif=this.inFlight[x];
if(!tif||tif.http._aborted||!tif.http.readyState){
this.inFlight.splice(x,1);
continue;
}
if(4==tif.http.readyState){
this.inFlight.splice(x,1);
doLoad(tif.req,tif.http,tif.url,tif.query,tif.useCache);
}else{
if(tif.startTime){
if(!now){
now=(new Date()).getTime();
}
if(tif.startTime+(tif.req.timeoutSeconds*1000)<now){
if(typeof tif.http.abort=="function"){
tif.http.abort();
}
this.inFlight.splice(x,1);
tif.req[(typeof tif.req.timeout=="function")?"timeout":"handle"]("timeout",null,tif.http,tif.req);
}
}
}
}
}
clearTimeout(this.inFlightTimer);
if(this.inFlight.length==0){
this.inFlightTimer=null;
return;
}
this.inFlightTimer=setTimeout("dojo.io.XMLHTTPTransport.watchInFlight();",10);
};
var _749=dojo.hostenv.getXmlhttpObject()?true:false;
this.canHandle=function(_74a){
return _749&&dojo.lang.inArray(["text/plain","text/html","application/xml","text/xml","text/javascript","text/json"],(_74a["mimetype"].toLowerCase()||""))&&!(_74a["formNode"]&&dojo.io.formHasFile(_74a["formNode"]));
};
this.multipartBoundary="45309FFF-BD65-4d50-99C9-36986896A96F";
this.bind=function(_74b){
if(!_74b["url"]){
if(!_74b["formNode"]&&(_74b["backButton"]||_74b["back"]||_74b["changeUrl"]||_74b["watchForURL"])&&(!djConfig.preventBackButtonFix)){
dojo.deprecated("Using dojo.io.XMLHTTPTransport.bind() to add to browser history without doing an IO request","Use dojo.undo.browser.addToHistory() instead.","0.4");
dojo.undo.browser.addToHistory(_74b);
return true;
}
}
var url=_74b.url;
var _74d="";
if(_74b["formNode"]){
var ta=_74b.formNode.getAttribute("action");
if((ta)&&(!_74b["url"])){
url=ta;
}
var tp=_74b.formNode.getAttribute("method");
if((tp)&&(!_74b["method"])){
_74b.method=tp;
}
_74d+=dojo.io.encodeForm(_74b.formNode,_74b.encoding,_74b["formFilter"]);
}
if(url.indexOf("#")>-1){
dojo.debug("Warning: dojo.io.bind: stripping hash values from url:",url);
url=url.split("#")[0];
}
if(_74b["file"]){
_74b.method="post";
}
if(!_74b["method"]){
_74b.method="get";
}
if(_74b.method.toLowerCase()=="get"){
_74b.multipart=false;
}else{
if(_74b["file"]){
_74b.multipart=true;
}else{
if(!_74b["multipart"]){
_74b.multipart=false;
}
}
}
if(_74b["backButton"]||_74b["back"]||_74b["changeUrl"]){
dojo.undo.browser.addToHistory(_74b);
}
var _750=_74b["content"]||{};
if(_74b.sendTransport){
_750["dojo.transport"]="xmlhttp";
}
do{
if(_74b.postContent){
_74d=_74b.postContent;
break;
}
if(_750){
_74d+=dojo.io.argsFromMap(_750,_74b.encoding);
}
if(_74b.method.toLowerCase()=="get"||!_74b.multipart){
break;
}
var t=[];
if(_74d.length){
var q=_74d.split("&");
for(var i=0;i<q.length;++i){
if(q[i].length){
var p=q[i].split("=");
t.push("--"+this.multipartBoundary,"Content-Disposition: form-data; name=\""+p[0]+"\"","",p[1]);
}
}
}
if(_74b.file){
if(dojo.lang.isArray(_74b.file)){
for(var i=0;i<_74b.file.length;++i){
var o=_74b.file[i];
t.push("--"+this.multipartBoundary,"Content-Disposition: form-data; name=\""+o.name+"\"; filename=\""+("fileName" in o?o.fileName:o.name)+"\"","Content-Type: "+("contentType" in o?o.contentType:"application/octet-stream"),"",o.content);
}
}else{
var o=_74b.file;
t.push("--"+this.multipartBoundary,"Content-Disposition: form-data; name=\""+o.name+"\"; filename=\""+("fileName" in o?o.fileName:o.name)+"\"","Content-Type: "+("contentType" in o?o.contentType:"application/octet-stream"),"",o.content);
}
}
if(t.length){
t.push("--"+this.multipartBoundary+"--","");
_74d=t.join("\r\n");
}
}while(false);
var _756=_74b["sync"]?false:true;
var _757=_74b["preventCache"]||(this.preventCache==true&&_74b["preventCache"]!=false);
var _758=_74b["useCache"]==true||(this.useCache==true&&_74b["useCache"]!=false);
if(!_757&&_758){
var _759=getFromCache(url,_74d,_74b.method);
if(_759){
doLoad(_74b,_759,url,_74d,false);
return;
}
}
var http=dojo.hostenv.getXmlhttpObject(_74b);
var _75b=false;
if(_756){
var _75c=this.inFlight.push({"req":_74b,"http":http,"url":url,"query":_74d,"useCache":_758,"startTime":_74b.timeoutSeconds?(new Date()).getTime():0});
this.startWatchingInFlight();
}else{
_72c._blockAsync=true;
}
if(_74b.method.toLowerCase()=="post"){
http.open("POST",url,_756);
setHeaders(http,_74b);
http.setRequestHeader("Content-Type",_74b.multipart?("multipart/form-data; boundary="+this.multipartBoundary):(_74b.contentType||"application/x-www-form-urlencoded"));
try{
http.send(_74d);
}
catch(e){
if(typeof http.abort=="function"){
http.abort();
}
doLoad(_74b,{status:404},url,_74d,_758);
}
}else{
var _75d=url;
if(_74d!=""){
_75d+=(_75d.indexOf("?")>-1?"&":"?")+_74d;
}
if(_757){
_75d+=(dojo.string.endsWithAny(_75d,"?","&")?"":(_75d.indexOf("?")>-1?"&":"?"))+"dojo.preventCache="+new Date().valueOf();
}
http.open(_74b.method.toUpperCase(),_75d,_756);
setHeaders(http,_74b);
try{
http.send(null);
}
catch(e){
if(typeof http.abort=="function"){
http.abort();
}
doLoad(_74b,{status:404},url,_74d,_758);
}
}
if(!_756){
doLoad(_74b,http,url,_74d,_758);
_72c._blockAsync=false;
}
_74b.abort=function(){
try{
http._aborted=true;
}
catch(e){
}
return http.abort();
};
return;
};
dojo.io.transports.addTransport("XMLHTTPTransport");
};
dojo.provide("dojo.io.cookie");
dojo.io.cookie.setCookie=function(name,_75f,days,path,_762,_763){
var _764=-1;
if(typeof days=="number"&&days>=0){
var d=new Date();
d.setTime(d.getTime()+(days*24*60*60*1000));
_764=d.toGMTString();
}
_75f=escape(_75f);
document.cookie=name+"="+_75f+";"+(_764!=-1?" expires="+_764+";":"")+(path?"path="+path:"")+(_762?"; domain="+_762:"")+(_763?"; secure":"");
};
dojo.io.cookie.set=dojo.io.cookie.setCookie;
dojo.io.cookie.getCookie=function(name){
var idx=document.cookie.lastIndexOf(name+"=");
if(idx==-1){
return null;
}
var _768=document.cookie.substring(idx+name.length+1);
var end=_768.indexOf(";");
if(end==-1){
end=_768.length;
}
_768=_768.substring(0,end);
_768=unescape(_768);
return _768;
};
dojo.io.cookie.get=dojo.io.cookie.getCookie;
dojo.io.cookie.deleteCookie=function(name){
dojo.io.cookie.setCookie(name,"-",0);
};
dojo.io.cookie.setObjectCookie=function(name,obj,days,path,_76f,_770,_771){
if(arguments.length==5){
_771=_76f;
_76f=null;
_770=null;
}
var _772=[],cookie,value="";
if(!_771){
cookie=dojo.io.cookie.getObjectCookie(name);
}
if(days>=0){
if(!cookie){
cookie={};
}
for(var prop in obj){
if(prop==null){
delete cookie[prop];
}else{
if(typeof obj[prop]=="string"||typeof obj[prop]=="number"){
cookie[prop]=obj[prop];
}
}
}
prop=null;
for(var prop in cookie){
_772.push(escape(prop)+"="+escape(cookie[prop]));
}
value=_772.join("&");
}
dojo.io.cookie.setCookie(name,value,days,path,_76f,_770);
};
dojo.io.cookie.getObjectCookie=function(name){
var _775=null,cookie=dojo.io.cookie.getCookie(name);
if(cookie){
_775={};
var _776=cookie.split("&");
for(var i=0;i<_776.length;i++){
var pair=_776[i].split("=");
var _779=pair[1];
if(isNaN(_779)){
_779=unescape(pair[1]);
}
_775[unescape(pair[0])]=_779;
}
}
return _775;
};
dojo.io.cookie.isSupported=function(){
if(typeof navigator.cookieEnabled!="boolean"){
dojo.io.cookie.setCookie("__TestingYourBrowserForCookieSupport__","CookiesAllowed",90,null);
var _77a=dojo.io.cookie.getCookie("__TestingYourBrowserForCookieSupport__");
navigator.cookieEnabled=(_77a=="CookiesAllowed");
if(navigator.cookieEnabled){
this.deleteCookie("__TestingYourBrowserForCookieSupport__");
}
}
return navigator.cookieEnabled;
};
if(!dojo.io.cookies){
dojo.io.cookies=dojo.io.cookie;
}
dojo.provide("dojo.io.*");
dojo.provide("dojo.html.*");
dojo.provide("dojo.html.iframe");
dojo.html.iframeContentWindow=function(_77b){
var win=dojo.html.getDocumentWindow(dojo.html.iframeContentDocument(_77b))||dojo.html.iframeContentDocument(_77b).__parent__||(_77b.name&&document.frames[_77b.name])||null;
return win;
};
dojo.html.iframeContentDocument=function(_77d){
var doc=_77d.contentDocument||((_77d.contentWindow)&&(_77d.contentWindow.document))||((_77d.name)&&(document.frames[_77d.name])&&(document.frames[_77d.name].document))||null;
return doc;
};
dojo.html.BackgroundIframe=function(node){
if(dojo.render.html.ie55||dojo.render.html.ie60){
var html="<iframe "+"style='position: absolute; left: 0px; top: 0px; width: 100%; height: 100%;"+"z-index: -1; filter:Alpha(Opacity=\"0\");' "+">";
this.iframe=dojo.doc().createElement(html);
this.iframe.tabIndex=-1;
if(node){
node.appendChild(this.iframe);
this.domNode=node;
}else{
dojo.body().appendChild(this.iframe);
this.iframe.style.display="none";
}
}
};
dojo.lang.extend(dojo.html.BackgroundIframe,{iframe:null,onResized:function(){
if(this.iframe&&this.domNode&&this.domNode.parentNode){
var _781=dojo.html.getBorderBox(this.domNode);
if(_781.width==0||_781.height==0){
dojo.lang.setTimeout(this,this.onResized,100);
return;
}
with(this.iframe.style){
width=_781.width+"px";
height=_781.height+"px";
}
}
},size:function(node){
if(!this.iframe){
return;
}
var _783=dojo.html.toCoordinateObject(node,true);
with(this.iframe.style){
width=_783.width+"px";
height=_783.height+"px";
left=_783.left+"px";
top=_783.top+"px";
}
},setZIndex:function(node){
if(!this.iframe){
return;
}
if(dojo.dom.isNode(node)){
this.iframe.style.zIndex=dojo.html.getStyle(node,"z-index")-1;
}else{
if(!isNaN(node)){
this.iframe.style.zIndex=node;
}
}
},show:function(){
if(!this.iframe){
return;
}
this.iframe.style.display="block";
},hide:function(){
if(!this.iframe){
return;
}
this.iframe.style.display="none";
},remove:function(){
dojo.dom.removeNode(this.iframe);
}});
dojo.provide("dojo.widget.html.stabile");
dojo.widget.html.stabile={_sqQuotables:new RegExp("([\\\\'])","g"),_depth:0,_recur:false,depthLimit:2};
dojo.widget.html.stabile.getState=function(id){
dojo.widget.html.stabile.setup();
return dojo.widget.html.stabile.widgetState[id];
};
dojo.widget.html.stabile.setState=function(id,_787,_788){
dojo.widget.html.stabile.setup();
dojo.widget.html.stabile.widgetState[id]=_787;
if(_788){
dojo.widget.html.stabile.commit(dojo.widget.html.stabile.widgetState);
}
};
dojo.widget.html.stabile.setup=function(){
if(!dojo.widget.html.stabile.widgetState){
var text=dojo.widget.html.stabile.getStorage().value;
dojo.widget.html.stabile.widgetState=text?dj_eval("("+text+")"):{};
}
};
dojo.widget.html.stabile.commit=function(_78a){
dojo.widget.html.stabile.getStorage().value=dojo.widget.html.stabile.description(_78a);
};
dojo.widget.html.stabile.description=function(v,_78c){
var _78d=dojo.widget.html.stabile._depth;
var _78e=function(){
return this.description(this,true);
};
try{
if(v===void (0)){
return "undefined";
}
if(v===null){
return "null";
}
if(typeof (v)=="boolean"||typeof (v)=="number"||v instanceof Boolean||v instanceof Number){
return v.toString();
}
if(typeof (v)=="string"||v instanceof String){
var v1=v.replace(dojo.widget.html.stabile._sqQuotables,"\\$1");
v1=v1.replace(/\n/g,"\\n");
v1=v1.replace(/\r/g,"\\r");
return "'"+v1+"'";
}
if(v instanceof Date){
return "new Date("+d.getFullYear+","+d.getMonth()+","+d.getDate()+")";
}
var d;
if(v instanceof Array||v.push){
if(_78d>=dojo.widget.html.stabile.depthLimit){
return "[ ... ]";
}
d="[";
var _791=true;
dojo.widget.html.stabile._depth++;
for(var i=0;i<v.length;i++){
if(_791){
_791=false;
}else{
d+=",";
}
d+=arguments.callee(v[i],_78c);
}
return d+"]";
}
if(v.constructor==Object||v.toString==_78e){
if(_78d>=dojo.widget.html.stabile.depthLimit){
return "{ ... }";
}
if(typeof (v.hasOwnProperty)!="function"&&v.prototype){
throw new Error("description: "+v+" not supported by script engine");
}
var _791=true;
d="{";
dojo.widget.html.stabile._depth++;
for(var key in v){
if(v[key]==void (0)||typeof (v[key])=="function"){
continue;
}
if(_791){
_791=false;
}else{
d+=", ";
}
var kd=key;
if(!kd.match(/^[a-zA-Z_][a-zA-Z0-9_]*$/)){
kd=arguments.callee(key,_78c);
}
d+=kd+": "+arguments.callee(v[key],_78c);
}
return d+"}";
}
if(_78c){
if(dojo.widget.html.stabile._recur){
var _795=Object.prototype.toString;
return _795.apply(v,[]);
}else{
dojo.widget.html.stabile._recur=true;
return v.toString();
}
}else{
throw new Error("Unknown type: "+v);
return "'unknown'";
}
}
finally{
dojo.widget.html.stabile._depth=_78d;
}
};
dojo.widget.html.stabile.getStorage=function(){
if(dojo.widget.html.stabile.dataField){
return dojo.widget.html.stabile.dataField;
}
var form=document.forms._dojo_form;
return dojo.widget.html.stabile.dataField=form?form.stabile:{value:""};
};
dojo.provide("dojo.html.selection");
dojo.html.selectionType={NONE:0,TEXT:1,CONTROL:2};
dojo.html.clearSelection=function(){
var _797=dojo.global();
var _798=dojo.doc();
try{
if(_797["getSelection"]){
if(dojo.render.html.safari){
_797.getSelection().collapse();
}else{
_797.getSelection().removeAllRanges();
}
}else{
if(_798.selection){
if(_798.selection.empty){
_798.selection.empty();
}else{
if(_798.selection.clear){
_798.selection.clear();
}
}
}
}
return true;
}
catch(e){
dojo.debug(e);
return false;
}
};
dojo.html.disableSelection=function(_799){
_799=dojo.byId(_799)||dojo.body();
var h=dojo.render.html;
if(h.mozilla){
_799.style.MozUserSelect="none";
}else{
if(h.safari){
_799.style.KhtmlUserSelect="none";
}else{
if(h.ie){
_799.unselectable="on";
}else{
return false;
}
}
}
return true;
};
dojo.html.enableSelection=function(_79b){
_79b=dojo.byId(_79b)||dojo.body();
var h=dojo.render.html;
if(h.mozilla){
_79b.style.MozUserSelect="";
}else{
if(h.safari){
_79b.style.KhtmlUserSelect="";
}else{
if(h.ie){
_79b.unselectable="off";
}else{
return false;
}
}
}
return true;
};
dojo.html.selectElement=function(_79d){
var _79e=dojo.global();
var _79f=dojo.doc();
_79d=dojo.byId(_79d);
if(_79f.selection&&dojo.body().createTextRange){
var _7a0=dojo.body().createTextRange();
_7a0.moveToElementText(_79d);
_7a0.select();
}else{
if(_79e["getSelection"]){
var _7a1=_79e.getSelection();
if(_7a1["selectAllChildren"]){
_7a1.selectAllChildren(_79d);
}
}
}
};
dojo.html.selectInputText=function(_7a2){
var _7a3=dojo.global();
var _7a4=dojo.doc();
_7a2=dojo.byId(_7a2);
if(_7a4.selection&&dojo.body().createTextRange){
var _7a5=_7a2.createTextRange();
_7a5.moveStart("character",0);
_7a5.moveEnd("character",_7a2.value.length);
_7a5.select();
}else{
if(_7a3["getSelection"]){
var _7a6=_7a3.getSelection();
_7a2.setSelectionRange(0,_7a2.value.length);
}
}
_7a2.focus();
};
dojo.html.isSelectionCollapsed=function(){
var _7a7=dojo.global();
var _7a8=dojo.doc();
if(_7a8["selection"]){
return _7a8.selection.createRange().text=="";
}else{
if(_7a7["getSelection"]){
var _7a9=_7a7.getSelection();
if(dojo.lang.isString(_7a9)){
return _7a9=="";
}else{
return _7a9.isCollapsed;
}
}
}
};
dojo.lang.mixin(dojo.html.selection,{getType:function(){
if(dojo.doc().selection){
return dojo.html.selectionType[dojo.doc().selection.type.toUpperCase()];
}else{
var _7aa=dojo.html.selectionType.TEXT;
var oSel;
try{
oSel=dojo.global().getSelection();
}
catch(e){
}
if(oSel&&oSel.rangeCount==1){
var _7ac=oSel.getRangeAt(0);
if(_7ac.startContainer==_7ac.endContainer&&(_7ac.endOffset-_7ac.startOffset)==1&&_7ac.startContainer.nodeType!=dojo.dom.TEXT_NODE){
_7aa=dojo.html.selectionType.CONTROL;
}
}
return _7aa;
}
},getSelectedElement:function(){
if(dojo.html.selection.getType()==dojo.html.selectionType.CONTROL){
if(dojo.doc().selection){
var _7ad=dojo.doc().selection.createRange();
if(_7ad&&_7ad.item){
return dojo.doc().selection.createRange().item(0);
}
}else{
var oSel=dojo.global().getSelection();
return oSel.anchorNode.childNodes[oSel.anchorOffset];
}
}
},getParentElement:function(){
if(dojo.html.selection.getType()==dojo.html.selectionType.CONTROL){
var p=dojo.html.selection.getSelectedElement();
if(p){
return p.parentNode;
}
}else{
if(dojo.doc().selection){
return dojo.doc().selection.createRange().parentElement();
}else{
var oSel=dojo.global().getSelection();
if(oSel){
var _7b1=oSel.anchorNode;
while(_7b1&&_7b1.nodeType!=1){
_7b1=_7b1.parentNode;
}
return _7b1;
}
}
}
},selectNode:function(node){
dojo.html.selectElement(node);
},collapse:function(){
dojo.html.clearSelection();
},remove:function(){
if(dojo.doc().selection){
var oSel=dojo.doc().selection;
if(oSel.type.toUpperCase()!="NONE"){
oSel.clear();
}
return oSel;
}else{
var oSel=dojo.global().getSelection();
for(var i=0;i<oSel.rangeCount;i++){
oSel.getRangeAt(i).deleteContents();
}
return oSel;
}
}});
dojo.provide("dojo.widget.PopupContainer");
dojo.provide("dojo.widget.Menu2");
dojo.provide("dojo.widget.PopupMenu2");
dojo.provide("dojo.widget.MenuItem2");
dojo.provide("dojo.widget.MenuBar2");
dojo.widget.defineWidget("dojo.widget.PopupContainer",dojo.widget.HtmlWidget,{initializer:function(){
this.queueOnAnimationFinish=[];
},isContainer:true,templateString:"<div dojoAttachPoint=\"containerNode\" style=\"display:none;\" class=\"dojoPopupContainer\" tabindex=\"-1\"></div>",templateCssString:".dojoPopupContainer{position:absolute;}",snarfChildDomOutput:true,isShowingNow:false,currentSubpopup:null,beginZIndex:1000,parentPopup:null,popupIndex:0,aroundBox:dojo.html.boxSizing.BORDER_BOX,processKey:function(evt){
return false;
},open:function(x,y,_7b8,_7b9,_7ba,_7bb){
if(this.isShowingNow){
return;
}
if(this.animationInProgress){
this.queueOnAnimationFinish.push(this.open,arguments);
return;
}
var _7bc=false,node,aroundOrient;
if(typeof x=="object"){
node=x;
aroundOrient=_7b9;
_7b9=_7b8;
_7b8=y;
_7bc=true;
}
dojo.body().appendChild(this.domNode);
_7b9=_7b9||_7b8["domNode"]||[];
var _7bd=null;
this.isTopLevel=true;
while(_7b8){
if(_7b8!==this&&_7b8 instanceof dojo.widget.PopupContainer){
_7bd=_7b8;
this.isTopLevel=false;
_7bd.setOpenedSubpopup(this);
break;
}
_7b8=_7b8.parent;
}
this.parentPopup=_7bd;
this.popupIndex=_7bd?_7bd.popupIndex+1:1;
if(this.isTopLevel){
var _7be=_7b9 instanceof Array?null:_7b9;
dojo.widget.PopupManager.opened(this,_7be);
}
if(_7b9 instanceof Array){
_7b9={left:_7b9[0],top:_7b9[1],width:0,height:0};
}
with(this.domNode.style){
display="";
zIndex=this.beginZIndex+this.popupIndex;
}
if(_7bc){
this.move(node,_7bb,aroundOrient);
}else{
this.move(x,y,_7bb,_7ba);
}
this.domNode.style.display="none";
this.explodeSrc=_7b9;
this.show();
this.isShowingNow=true;
},move:function(x,y,_7c1,_7c2){
var _7c3=(typeof x=="object");
if(_7c3){
var _7c4=_7c1;
var node=x;
_7c1=y;
if(!_7c4){
_7c4={"BL":"TL","TL":"BL"};
}
dojo.html.placeOnScreenAroundElement(this.domNode,node,_7c1,this.aroundBox,_7c4);
}else{
if(!_7c2){
_7c2="TL,TR,BL,BR";
}
dojo.html.placeOnScreen(this.domNode,x,y,_7c1,true,_7c2);
}
},close:function(){
if(this.animationInProgress){
this.queueOnAnimationFinish.push(this.close,[]);
return;
}
this.closeSubpopup();
this.hide();
if(this.bgIframe){
this.bgIframe.hide();
this.bgIframe.size({left:0,top:0,width:0,height:0});
}
if(this.isTopLevel){
dojo.widget.PopupManager.closed(this);
}
this.isShowingNow=false;
},closeAll:function(){
if(this.parentPopup){
this.parentPopup.closeAll();
}else{
this.close();
}
},setOpenedSubpopup:function(_7c6){
this.currentSubpopup=_7c6;
},closeSubpopup:function(){
if(this.currentSubpopup==null){
return;
}
this.currentSubpopup.close();
this.currentSubpopup=null;
},onShow:function(){
dojo.widget.PopupContainer.superclass.onShow.call(this);
this.openedSize={w:this.domNode.style.width,h:this.domNode.style.height};
if(dojo.render.html.ie){
if(!this.bgIframe){
this.bgIframe=new dojo.html.BackgroundIframe();
this.bgIframe.setZIndex(this.domNode);
}
this.bgIframe.size(this.domNode);
this.bgIframe.show();
}
this.processQueue();
},processQueue:function(){
if(!this.queueOnAnimationFinish.length){
return;
}
var func=this.queueOnAnimationFinish.shift();
var args=this.queueOnAnimationFinish.shift();
func.apply(this,args);
},onHide:function(){
dojo.widget.HtmlWidget.prototype.onHide.call(this);
if(this.openedSize){
with(this.domNode.style){
width=this.openedSize.w;
height=this.openedSize.h;
}
}
this.processQueue();
}});
dojo.widget.defineWidget("dojo.widget.PopupMenu2",dojo.widget.PopupContainer,{initializer:function(){
dojo.widget.PopupMenu2.superclass.initializer.call(this);
this.targetNodeIds=[];
this.eventNames={open:""};
},templateCssString:"",currentSubmenuTrigger:null,eventNaming:"default",templateString:"<table class=\"dojoPopupMenu2\" border=0 cellspacing=0 cellpadding=0 style=\"display: none;\"><tbody dojoAttachPoint=\"containerNode\"></tbody></table>",templateCssString:"\n.dojoPopupMenu2 {\n	position: absolute;\n	border: 1px solid #7298d0;\n	background:#a9ccfe url(images/soriaMenuBg.gif) repeat-x bottom left !important;\n	padding: 1px;\n	margin-top: 1px;\n	margin-bottom: 1px;\n}\n\n.dojoMenuItem2, .dojoMenuItem2 span span {\n	white-space: nowrap;\n	font: menu;\n	margin: 0;\n}\n\n.dojoMenuItem2 span {\n	margin: 0;\n	padding-right:5px;\n}\n\n.dojoMenuItem2Hover {\n	background-color: #D2E4FD;\n	cursor:pointer;\n	cursor:hand;\n}\n\n.dojoMenuItem2Icon {\n	position: relative;\n	background-position: center center;\n	background-repeat: no-repeat;\n	z-index: 1;\n	width: 16px;\n	height: 16px;\n}\n\n.dojoMenuItem2Label {\n	position: relative;\n	vertical-align: middle;\n	z-index: 1;\n}\n\n/* main label text */\n.dojoMenuItem2Label span {\n	position: relative;\n	vertical-align: middle;\n	z-index: 2;\n}\n\n/* label shadow text */\n.dojoMenuItem2Label span span {\n	position: absolute;\n	display: none;\n	left: 1px;\n	top: 1px;\n	z-index: -2;\n}\n\n.dojoMenuItem2Accel {\n	position: relative;\n	vertical-align: middle;\n	z-index: 1;\n}\n\n/* accelerator string */\n.dojoMenuItem2Accel span {\n	position: relative;\n	vertical-align: middle;\n	z-index: 2;\n}\n\n/* accelerator string shadow */\n.dojoMenuItem2Accel span span {\n	position: absolute;\n	display: none;\n	left: 1px;\n	top: 1px;\n	z-index: -2;\n}\n\n.dojoMenuItem2Disabled .dojoMenuItem2Label span,\n.dojoMenuItem2Disabled .dojoMenuItem2Accel span {\n	color: #607a9e;\n}\n\n.dojoMenuItem2Disabled .dojoMenuItem2Label span span,\n.dojoMenuItem2Disabled .dojoMenuItem2Accel span span {\n	display: block;\n}\n\n.dojoMenuItem2Hover .dojoMenuItem2Label span span,\n.dojoMenuItem2Hover .dojoMenuItem2Accel span span {\n	display: none;\n}\n\n.dojoMenuItem2Submenu {\n	position: relative;\n	background-position: center center;\n	background-repeat: no-repeat;\n	background-image: url(images/submenu_off.gif);\n	width: 5px;\n	height: 9px;\n}\n.dojoMenuItem2Hover .dojoMenuItem2Submenu {\n	background-image: url(images/submenu_on.gif);\n}\n\n.dojoMenuSeparator2 {\n	font-size: 1px;\n	margin: 0;\n}\n\n.dojoMenuSeparator2Top {\n	height: 50%;\n	border-bottom: 1px solid #7996c1;\n	margin: 0px 2px;\n	font-size: 1px;\n}\n\n.dojoMenuSeparator2Bottom {\n	height: 50%;\n	border-top: 1px solid #e3eeff;\n	margin: 0px 2px;\n	font-size: 1px;\n}\n\n.dojoMenuBar2 {\n	/*position: relative;*/\n	background:#a9ccfe url(images/soriaBarBg.gif) repeat-x bottom left;\n	border-bottom:1px solid #405067;\n	border-top:1px solid #708bb3;\n}\n\n.dojoMenuBar2Client {\n	padding: 1px;\n}\n\n.dojoMenuBarItem2 {\n	white-space: nowrap;\n	font: menu;\n	margin: 0;\n	position: relative;\n	vertical-align: middle;\n	z-index: 1;\n	padding: 3px 8px;\n}\n\n.dojoMenuBarItem2 span {\n	margin: 0;\n	position: relative;\n	z-index: 2;\n	cursor:pointer;\n	cursor:hand;\n}\n\n.dojoMenuBarItem2 span span {\n	position: absolute;\n	display: none;\n	left: 1px;\n	top: 1px;\n	z-index: -2;\n}\n\n.dojoMenuBarItem2Hover {\n	background-color:#d2e4fd;\n}\n\n.dojoMenuBarItem2Disabled span {\n	color: #4f6582;\n}\n\n.dojoMenuBarItem2Disabled span span {\n	display: block;\n}\n\n.dojoMenuBarItem2Hover span span,\n.dojoMenuBarItem2Hover span span {\n	display: none;\n}\n",templateCssPath:dojo.uri.dojoUri("src/widget/templates/HtmlMenu2.css"),submenuDelay:500,submenuOverlap:5,contextMenuForWindow:false,openEvent:null,_highlighted_option:null,initialize:function(args,frag){
if(this.eventNaming=="default"){
for(var _7cb in this.eventNames){
this.eventNames[_7cb]=this.widgetId+"/"+_7cb;
}
}
},postCreate:function(){
if(this.contextMenuForWindow){
var doc=dojo.body();
this.bindDomNode(doc);
}else{
if(this.targetNodeIds.length>0){
dojo.lang.forEach(this.targetNodeIds,this.bindDomNode,this);
}
}
this.subscribeSubitemsOnOpen();
},subscribeSubitemsOnOpen:function(){
var _7cd=this.getChildrenOfType(dojo.widget.MenuItem2);
for(var i=0;i<_7cd.length;i++){
dojo.event.topic.subscribe(this.eventNames.open,_7cd[i],"menuOpen");
}
},getTopOpenEvent:function(){
var menu=this;
while(menu.parentPopup){
menu=menu.parentPopup;
}
return menu.openEvent;
},bindDomNode:function(node){
node=dojo.byId(node);
var win=dojo.html.getElementWindow(node);
if(dojo.html.isTag(node,"iframe")=="iframe"){
win=dojo.html.iframeContentWindow(node);
node=dojo.withGlobal(win,dojo.body);
}
dojo.widget.Menu2.OperaAndKonqFixer.fixNode(node);
dojo.event.kwConnect({srcObj:node,srcFunc:"oncontextmenu",targetObj:this,targetFunc:"onOpen",once:true});
dojo.widget.PopupManager.registerWin(win);
},unBindDomNode:function(_7d2){
var node=dojo.byId(_7d2);
dojo.event.kwDisconnect({srcObj:node,srcFunc:"oncontextmenu",targetObj:this,targetFunc:"onOpen",once:true});
dojo.widget.Menu2.OperaAndKonqFixer.cleanNode(node);
},moveToNext:function(evt){
this.highlightOption(1);
return true;
},moveToPrevious:function(evt){
this.highlightOption(-1);
return true;
},moveToParentMenu:function(evt){
if(this._highlighted_option&&this.parentPopup){
if(evt._menu2UpKeyProcessed){
return true;
}else{
this._highlighted_option.onUnhover();
this.closeSubpopup();
evt._menu2UpKeyProcessed=true;
}
}
return false;
},moveToChildMenu:function(evt){
if(this._highlighted_option&&this._highlighted_option.submenuId){
this._highlighted_option._onClick(true);
return true;
}
return false;
},selectCurrentItem:function(evt){
if(this._highlighted_option){
this._highlighted_option._onClick();
return true;
}
return false;
},processKey:function(evt){
if(evt.ctrlKey||evt.altKey){
return false;
}
var _7da=evt.keyCode;
var rval=false;
var k=dojo.event.browser.keys;
var _7da=evt.keyCode;
if(_7da==0&&evt.charCode==k.KEY_SPACE){
_7da=k.KEY_SPACE;
}
switch(_7da){
case k.KEY_DOWN_ARROW:
rval=this.moveToNext(evt);
break;
case k.KEY_UP_ARROW:
rval=this.moveToPrevious(evt);
break;
case k.KEY_RIGHT_ARROW:
rval=this.moveToChildMenu(evt);
break;
case k.KEY_LEFT_ARROW:
rval=this.moveToParentMenu(evt);
break;
case k.KEY_SPACE:
case k.KEY_ENTER:
if(rval=this.selectCurrentItem(evt)){
break;
}
case k.KEY_ESCAPE:
dojo.widget.PopupManager.currentMenu.close();
rval=true;
break;
}
return rval;
},findValidItem:function(dir,_7de){
if(_7de){
_7de=dir>0?_7de.getNextSibling():_7de.getPreviousSibling();
}
for(var i=0;i<this.children.length;++i){
if(!_7de){
_7de=dir>0?this.children[0]:this.children[this.children.length-1];
}
if(_7de.onHover){
return _7de;
}
_7de=dir>0?_7de.getNextSibling():_7de.getPreviousSibling();
}
},highlightOption:function(dir){
var item;
if((!this._highlighted_option)){
item=this.findValidItem(dir);
}else{
item=this.findValidItem(dir,this._highlighted_option);
}
if(item){
if(this._highlighted_option){
this._highlighted_option.onUnhover();
}
item.onHover();
dojo.html.scrollIntoView(item.domNode);
}
},onItemClick:function(item){
},close:function(){
if(this.animationInProgress){
dojo.widget.PopupMenu2.superclass.close.call(this);
return;
}
if(this._highlighted_option){
this._highlighted_option.onUnhover();
}
dojo.widget.PopupMenu2.superclass.close.call(this);
},closeSubpopup:function(){
if(this.currentSubpopup==null){
return;
}
this.currentSubpopup.close();
this.currentSubpopup=null;
this.currentSubmenuTrigger.is_open=false;
this.currentSubmenuTrigger.closedSubmenu();
this.currentSubmenuTrigger=null;
},openSubmenu:function(_7e3,_7e4){
var _7e5=dojo.html.getAbsolutePosition(_7e4.domNode,true);
var _7e6=dojo.html.getMarginBox(this.domNode).width;
var x=_7e5.x+_7e6-this.submenuOverlap;
var y=_7e5.y;
_7e3.open(x,y,this,_7e4.domNode);
this.currentSubmenuTrigger=_7e4;
this.currentSubmenuTrigger.is_open=true;
},onOpen:function(e){
this.openEvent=e;
var x=e.pageX,y=e.pageY;
var win=dojo.html.getElementWindow(e.target);
var _7ec=win.frameElement;
if(_7ec){
var cood=dojo.html.getAbsolutePosition(_7ec,true);
x+=cood.x-dojo.withGlobal(win,dojo.html.getScroll).left;
y+=cood.y-dojo.withGlobal(win,dojo.html.getScroll).top;
}
this.open(x,y,null,[x,y]);
e.preventDefault();
e.stopPropagation();
}});
dojo.widget.defineWidget("dojo.widget.MenuItem2",dojo.widget.HtmlWidget,{initializer:function(){
this.eventNames={engage:""};
},templateString:"<tr class=\"dojoMenuItem2\" dojoAttachEvent=\"onMouseOver: onHover; onMouseOut: onUnhover; onClick: _onClick;\">"+"<td><div class=\"dojoMenuItem2Icon\" style=\"${this.iconStyle}\"></div></td>"+"<td class=\"dojoMenuItem2Label\"><span><span>${this.caption}</span>${this.caption}</span></td>"+"<td class=\"dojoMenuItem2Accel\"><span><span>${this.accelKey}</span>${this.accelKey}</span></td>"+"<td><div class=\"dojoMenuItem2Submenu\" style=\"display:${this.arrowDisplay};\"></div></td>"+"</tr>",is_hovering:false,hover_timer:null,is_open:false,topPosition:0,caption:"Untitled",accelKey:"",iconSrc:"",submenuId:"",disabled:false,eventNaming:"default",highlightClass:"dojoMenuItem2Hover",postMixInProperties:function(){
this.iconStyle="";
if(this.iconSrc){
if((this.iconSrc.toLowerCase().substring(this.iconSrc.length-4)==".png")&&(dojo.render.html.ie)){
this.iconStyle="filter: progid:DXImageTransform.Microsoft.AlphaImageLoader(src='"+this.iconSrc+"', sizingMethod='image')";
}else{
this.iconStyle="background-image: url("+this.iconSrc+")";
}
}
this.arrowDisplay=this.submenuId?"block":"none";
},fillInTemplate:function(){
dojo.html.disableSelection(this.domNode);
if(this.disabled){
this.setDisabled(true);
}
if(this.eventNaming=="default"){
for(var _7ee in this.eventNames){
this.eventNames[_7ee]=this.widgetId+"/"+_7ee;
}
}
},onHover:function(){
this.onUnhover();
if(this.is_hovering){
return;
}
if(this.is_open){
return;
}
if(this.parent._highlighted_option){
this.parent._highlighted_option.onUnhover();
}
this.parent.closeSubpopup();
this.parent._highlighted_option=this;
dojo.widget.PopupManager.setFocusedMenu(this.parent);
this.highlightItem();
if(this.is_hovering){
this.stopSubmenuTimer();
}
this.is_hovering=true;
this.startSubmenuTimer();
},onUnhover:function(){
if(!this.is_open){
this.unhighlightItem();
}
this.is_hovering=false;
this.parent._highlighted_option=null;
if(this.parent.parentPopup){
dojo.widget.PopupManager.setFocusedMenu(this.parent.parentPopup);
}
this.stopSubmenuTimer();
},_onClick:function(_7ef){
var _7f0=false;
if(this.disabled){
return false;
}
if(this.submenuId){
if(!this.is_open){
this.stopSubmenuTimer();
this.openSubmenu();
}
_7f0=true;
}else{
this.parent.closeAll();
}
if(!_7f0){
this.onUnhover();
}
this.onClick();
dojo.event.topic.publish(this.eventNames.engage,this);
if(_7f0&&_7ef){
dojo.widget.getWidgetById(this.submenuId).highlightOption(1);
}
return;
},onClick:function(){
this.parent.onItemClick(this);
},highlightItem:function(){
dojo.html.addClass(this.domNode,this.highlightClass);
},unhighlightItem:function(){
dojo.html.removeClass(this.domNode,this.highlightClass);
},startSubmenuTimer:function(){
this.stopSubmenuTimer();
if(this.disabled){
return;
}
var self=this;
var _7f2=function(){
return function(){
self.openSubmenu();
};
}();
this.hover_timer=dojo.lang.setTimeout(_7f2,this.parent.submenuDelay);
},stopSubmenuTimer:function(){
if(this.hover_timer){
dojo.lang.clearTimeout(this.hover_timer);
this.hover_timer=null;
}
},openSubmenu:function(){
this.parent.closeSubpopup();
var _7f3=dojo.widget.getWidgetById(this.submenuId);
if(_7f3){
this.parent.openSubmenu(_7f3,this);
}
},closedSubmenu:function(){
this.onUnhover();
},setDisabled:function(_7f4){
this.disabled=_7f4;
if(this.disabled){
dojo.html.addClass(this.domNode,"dojoMenuItem2Disabled");
}else{
dojo.html.removeClass(this.domNode,"dojoMenuItem2Disabled");
}
},enable:function(){
this.setDisabled(false);
},disable:function(){
this.setDisabled(true);
},menuOpen:function(_7f5){
}});
dojo.widget.defineWidget("dojo.widget.MenuSeparator2",dojo.widget.HtmlWidget,{templateString:"<tr class=\"dojoMenuSeparator2\"><td colspan=4>"+"<div class=\"dojoMenuSeparator2Top\"></div>"+"<div class=\"dojoMenuSeparator2Bottom\"></div>"+"</td></tr>",postCreate:function(){
dojo.html.disableSelection(this.domNode);
}});
dojo.widget.PopupManager=new function(){
this.currentMenu=null;
this.currentButton=null;
this.currentFocusMenu=null;
this.focusNode=null;
this.registeredWindows=[];
this._keyEventName=dojo.doc().createEvent?"onkeypress":"onkeydown";
this.registerWin=function(win){
if(!win.__PopupManagerRegistered){
dojo.event.connect(win.document,"onmousedown",this,"onClick");
dojo.event.connect(win,"onscroll",this,"onClick");
dojo.event.connect(win.document,this._keyEventName,this,"onKeyPress");
win.__PopupManagerRegistered=true;
this.registeredWindows.push(win);
}
};
this.registerAllWindows=function(_7f7){
if(!_7f7){
_7f7=dojo.html.getDocumentWindow(window.top.document);
}
this.registerWin(_7f7);
for(var i=0;i<_7f7.frames.length;i++){
var win=dojo.html.getDocumentWindow(_7f7.frames[i].document);
if(win){
this.registerAllWindows(win);
}
}
};
dojo.addOnLoad(this,"registerAllWindows");
this.closed=function(menu){
if(this.currentMenu==menu){
this.currentMenu=null;
this.currentButton=null;
this.currentFocusMenu=null;
}
};
this.opened=function(menu,_7fc){
if(menu==this.currentMenu){
return;
}
if(this.currentMenu){
this.currentMenu.close();
}
this.currentMenu=menu;
this.currentFocusMenu=menu;
this.currentButton=_7fc;
};
this.setFocusedMenu=function(menu){
this.currentFocusMenu=menu;
};
this.onKeyPress=function(e){
if(!this.currentMenu||!this.currentMenu.isShowingNow){
return;
}
var m=this.currentFocusMenu;
while(m){
if(m.processKey(e)){
e.preventDefault();
e.stopPropagation();
break;
}
m=m.parentPopup;
}
},this.onClick=function(e){
if(!this.currentMenu){
return;
}
var _801=dojo.html.getScroll().offset;
var m=this.currentMenu;
while(m){
if(dojo.html.overElement(m.domNode,e)||dojo.html.isDescendantOf(e.target,m.domNode)){
return;
}
m=m.currentSubpopup;
}
if(this.currentButton&&dojo.html.overElement(this.currentButton,e)){
return;
}
this.currentMenu.close();
};
};
dojo.widget.Menu2.OperaAndKonqFixer=new function(){
var _803=true;
var _804=false;
if(!dojo.lang.isFunction(dojo.doc().oncontextmenu)){
dojo.doc().oncontextmenu=function(){
_803=false;
_804=true;
};
}
if(dojo.doc().createEvent){
try{
var e=dojo.doc().createEvent("MouseEvents");
e.initMouseEvent("contextmenu",1,1,dojo.global(),1,0,0,0,0,0,0,0,0,0,null);
dojo.doc().dispatchEvent(e);
}
catch(e){
}
}else{
_803=false;
}
if(_804){
delete dojo.doc().oncontextmenu;
}
this.fixNode=function(node){
if(_803){
if(!dojo.lang.isFunction(node.oncontextmenu)){
node.oncontextmenu=function(e){
};
}
if(dojo.render.html.opera){
node._menufixer_opera=function(e){
if(e.ctrlKey){
this.oncontextmenu(e);
}
};
dojo.event.connect(node,"onclick",node,"_menufixer_opera");
}else{
node._menufixer_konq=function(e){
if(e.button==2){
e.preventDefault();
this.oncontextmenu(e);
}
};
dojo.event.connect(node,"onmousedown",node,"_menufixer_konq");
}
}
};
this.cleanNode=function(node){
if(_803){
if(node._menufixer_opera){
dojo.event.disconnect(node,"onclick",node,"_menufixer_opera");
delete node._menufixer_opera;
}else{
if(node._menufixer_konq){
dojo.event.disconnect(node,"onmousedown",node,"_menufixer_konq");
delete node._menufixer_konq;
}
}
if(node.oncontextmenu){
delete node.oncontextmenu;
}
}
};
};
dojo.widget.defineWidget("dojo.widget.MenuBar2",dojo.widget.PopupMenu2,{menuOverlap:2,templateString:"<div class=\"dojoMenuBar2\"><table class=\"dojoMenuBar2Client\"><tr dojoAttachPoint=\"containerNode\"></tr></table></div>",close:function(){
if(this._highlighted_option){
this._highlighted_option.onUnhover();
}
this.closeSubpopup();
},processKey:function(evt){
if(evt.ctrlKey||evt.altKey){
return false;
}
var _80c=evt.keyCode;
var rval=false;
var k=dojo.event.browser.keys;
switch(_80c){
case k.KEY_DOWN_ARROW:
rval=this.moveToChildMenu(evt);
break;
case k.KEY_UP_ARROW:
rval=this.moveToParentMenu(evt);
break;
case k.KEY_RIGHT_ARROW:
rval=this.moveToNext(evt);
break;
case k.KEY_LEFT_ARROW:
rval=this.moveToPrevious(evt);
break;
default:
rval=this.inherited("processKey",evt);
break;
}
return rval;
},postCreate:function(){
this.inherited("postCreate");
dojo.widget.PopupManager.opened(this);
this.isShowingNow=true;
},openSubmenu:function(_80f,_810){
var _811=dojo.html.getAbsolutePosition(_810.domNode,true);
var _812=dojo.html.getAbsolutePosition(this.domNode,true);
var _813=dojo.html.getBorderBox(this.domNode).height;
var x=_811.x;
var y=_812.y+_813-this.menuOverlap;
_80f.open(x,y,this,_810.domNode);
this.currentSubmenuTrigger=_810;
this.currentSubmenuTrigger.is_open=true;
}});
dojo.widget.defineWidget("dojo.widget.MenuBarItem2",dojo.widget.MenuItem2,{templateString:"<td class=\"dojoMenuBarItem2\" dojoAttachEvent=\"onMouseOver: onHover; onMouseOut: onUnhover; onClick: _onClick;\">"+"<span><span>${this.caption}</span>${this.caption}</span>"+"</td>",highlightClass:"dojoMenuBarItem2Hover",setDisabled:function(_816){
this.disabled=_816;
if(this.disabled){
dojo.html.addClass(this.domNode,"dojoMenuBarItem2Disabled");
}else{
dojo.html.removeClass(this.domNode,"dojoMenuBarItem2Disabled");
}
}});
dojo.provide("dojo.widget.ComboBox");
dojo.widget.incrementalComboBoxDataProvider=function(url,_818,_819){
this.searchUrl=url;
this.inFlight=false;
this.activeRequest=null;
this.allowCache=false;
this.cache={};
this.init=function(cbox){
this.searchUrl=cbox.dataUrl;
};
this.addToCache=function(_81b,data){
if(this.allowCache){
this.cache[_81b]=data;
}
};
this.startSearch=function(_81d,type,_81f){
if(this.inFlight){
}
var tss=encodeURIComponent(_81d);
var _821=dojo.string.substituteParams(this.searchUrl,{"searchString":tss});
var _822=this;
var _823=dojo.io.bind({url:_821,method:"get",mimetype:"text/json",load:function(type,data,evt){
_822.inFlight=false;
if(!dojo.lang.isArray(data)){
var _827=[];
for(var key in data){
_827.push([data[key],key]);
}
data=_827;
}
_822.addToCache(_81d,data);
_822.provideSearchResults(data);
}});
this.inFlight=true;
};
};
dojo.widget.ComboBoxDataProvider=function(_829,_82a,_82b){
this.data=[];
this.searchTimeout=_82b||500;
this.searchLimit=_82a||30;
this.searchType="STARTSTRING";
this.caseSensitive=false;
this._lastSearch="";
this._lastSearchResults=null;
this.init=function(cbox,node){
if(!dojo.string.isBlank(cbox.dataUrl)){
this.getData(cbox.dataUrl);
}else{
if((node)&&(node.nodeName.toLowerCase()=="select")){
var opts=node.getElementsByTagName("option");
var ol=opts.length;
var data=[];
for(var x=0;x<ol;x++){
var _832=[String(opts[x].innerHTML),String(opts[x].value)];
data.push(_832);
if(opts[x].selected){
cbox.setAllValues(_832[0],_832[1]);
}
}
this.setData(data);
}
}
};
this.getData=function(url){
dojo.io.bind({url:url,load:dojo.lang.hitch(this,function(type,data,evt){
if(!dojo.lang.isArray(data)){
var _837=[];
for(var key in data){
_837.push([data[key],key]);
}
data=_837;
}
this.setData(data);
}),mimetype:"text/json"});
};
this.startSearch=function(_839,type,_83b){
this._preformSearch(_839,type,_83b);
};
this._preformSearch=function(_83c,type,_83e){
var st=type||this.searchType;
var ret=[];
if(!this.caseSensitive){
_83c=_83c.toLowerCase();
}
for(var x=0;x<this.data.length;x++){
if((!_83e)&&(ret.length>=this.searchLimit)){
break;
}
var _842=new String((!this.caseSensitive)?this.data[x][0].toLowerCase():this.data[x][0]);
if(_842.length<_83c.length){
continue;
}
if(st=="STARTSTRING"){
if(_83c==_842.substr(0,_83c.length)){
ret.push(this.data[x]);
}
}else{
if(st=="SUBSTRING"){
if(_842.indexOf(_83c)>=0){
ret.push(this.data[x]);
}
}else{
if(st=="STARTWORD"){
var idx=_842.indexOf(_83c);
if(idx==0){
ret.push(this.data[x]);
}
if(idx<=0){
continue;
}
var _844=false;
while(idx!=-1){
if(" ,/(".indexOf(_842.charAt(idx-1))!=-1){
_844=true;
break;
}
idx=_842.indexOf(_83c,idx+1);
}
if(!_844){
continue;
}else{
ret.push(this.data[x]);
}
}
}
}
}
this.provideSearchResults(ret);
};
this.provideSearchResults=function(_845){
};
this.addData=function(_846){
this.data=this.data.concat(_846);
};
this.setData=function(_847){
this.data=_847;
};
if(_829){
this.setData(_829);
}
};
dojo.widget.defineWidget("dojo.widget.ComboBox",dojo.widget.HtmlWidget,{isContainer:false,forceValidOption:false,searchType:"stringstart",dataProvider:null,startSearch:function(_848){
},selectNextResult:function(){
},selectPrevResult:function(){
},setSelectedResult:function(){
},autoComplete:true,formInputName:"",name:"",textInputNode:null,comboBoxValue:null,comboBoxSelectionValue:null,optionsListWrapper:null,optionsListNode:null,downArrowNode:null,cbTableNode:null,searchTimer:null,searchDelay:100,dataUrl:"",fadeTime:200,maxListLength:8,mode:"local",selectedResult:null,_highlighted_option:null,_prev_key_backspace:false,_prev_key_esc:false,_gotFocus:false,_mouseover_list:false,dataProviderClass:"dojo.widget.ComboBoxDataProvider",dropdownToggle:"fade",templateString:"<div style=\"position: relative; z-index: 100;\">\n	<input style=\"display:none\"  tabindex=\"-1\" name=\"\" value=\"\" \n		dojoAttachPoint=\"comboBoxValue\">\n	<input style=\"display:none\"  tabindex=\"-1\" name=\"\" value=\"\" \n		dojoAttachPoint=\"comboBoxSelectionValue\">\n	<table class=\"dojoComboBox\"\n		cellpadding=\"0\"\n		cellspacing=\"0\"\n		border=\"0\"\n		dojoAttachPoint=\"cbTableNode\">\n		<tr>\n			<td width=100%><input type=\"text\" autocomplete=\"off\" class=\"dojoComboBoxInput\"\n					dojoAttachEvent=\"keyDown: onKeyDown; keyUp: onKeyUp; keyPress: onKeyPress; compositionEnd\"\n					dojoAttachPoint=\"textInputNode\"\n					style=\"width: 100%;\"></td>\n			<td><img border=\"0\" \n					hspace=\"0\"\n					vspace=\"0\"\n					class=\"dojoComboArrow\"\n					dojoAttachPoint=\"downArrowNode\"\n					dojoAttachEvent=\"onMouseUp: handleArrowClick;\"\n					src=\"${dojoRoot}src/widget/templates/images/combo_box_arrow.png\"></td>\n		</tr>\n	</table>\n	</div>\n</div>\n",templateCssString:"input.dojoComboBoxInput {\n	/* font-size: 0.8em; */\n	border: 0px;\n	\n}\n\n.dojoComboBoxOptions {\n	font-family: Verdana, Helvetica, Garamond, sans-serif;\n	/* font-size: 0.7em; */\n	background-color: white;\n	border: 1px solid #afafaf;\n	position: absolute;\n	z-index: 1000; \n	overflow: auto;\n	cursor: default;\n}\n\ntable.dojoComboBox {\n	border: 1px solid #afafaf;\n}\n\n.dojoComboBoxItem {\n	padding-left: 2px;\n	padding-top: 2px;\n	margin: 0px;\n}\n\n.dojoComboBoxItemEven {\n	background-color: #f4f4f4;\n}\n\n.dojoComboBoxItemOdd {\n	background-color: white;\n}\n\n.dojoComboBoxItemHighlight {\n	background-color: #63709A;\n	color: white;\n}\n",templateCssPath:dojo.uri.dojoUri("src/widget/templates/HtmlComboBox.css"),setValue:function(_849){
this.comboBoxValue.value=_849;
if(this.textInputNode.value!=_849){
this.textInputNode.value=_849;
}
dojo.widget.html.stabile.setState(this.widgetId,this.getState(),true);
this.onValueChanged(_849);
},onValueChanged:function(){
},getValue:function(){
return this.comboBoxValue.value;
},getState:function(){
return {value:this.getValue()};
},setState:function(_84a){
this.setValue(_84a.value);
},getCaretPos:function(_84b){
if(dojo.lang.isNumber(_84b.selectionStart)){
return _84b.selectionStart;
}else{
if(dojo.render.html.ie){
var tr=document.selection.createRange().duplicate();
var ntr=_84b.createTextRange();
tr.move("character",0);
ntr.move("character",0);
try{
ntr.setEndPoint("EndToEnd",tr);
return String(ntr.text).replace(/\r/g,"").length;
}
catch(e){
return 0;
}
}
}
},setCaretPos:function(_84e,_84f){
_84f=parseInt(_84f);
this.setSelectedRange(_84e,_84f,_84f);
},setSelectedRange:function(_850,_851,end){
if(!end){
end=_850.value.length;
}
if(_850.setSelectionRange){
_850.focus();
_850.setSelectionRange(_851,end);
}else{
if(_850.createTextRange){
var _853=_850.createTextRange();
with(_853){
collapse(true);
moveEnd("character",end);
moveStart("character",_851);
select();
}
}else{
_850.value=_850.value;
_850.blur();
_850.focus();
var dist=parseInt(_850.value.length)-end;
var _855=String.fromCharCode(37);
var tcc=_855.charCodeAt(0);
for(var x=0;x<dist;x++){
var te=document.createEvent("KeyEvents");
te.initKeyEvent("keypress",true,true,null,false,false,false,false,tcc,tcc);
_850.dispatchEvent(te);
}
}
}
},_handleKeyEvents:function(evt){
if(evt.ctrlKey||evt.altKey){
return;
}
this._prev_key_backspace=false;
this._prev_key_esc=false;
var k=dojo.event.browser.keys;
var _85b=true;
var _85c=evt.keyCode;
if(_85c==0&&evt.charCode==k.KEY_SPACE){
_85c=k.KEY_SPACE;
}
if(dojo.render.html.safari){
switch(_85c){
case 63232:
_85c=k.KEY_UP_ARROW;
break;
case 63233:
_85c=k.KEY_DOWN_ARROW;
break;
}
}
switch(_85c){
case k.KEY_DOWN_ARROW:
if(!this.popupWidget.isShowingNow){
this.startSearchFromInput();
}
this.highlightNextOption();
dojo.event.browser.stopEvent(evt);
return;
case k.KEY_UP_ARROW:
this.highlightPrevOption();
dojo.event.browser.stopEvent(evt);
return;
case k.KEY_ENTER:
if(this.popupWidget.isShowingNow){
dojo.event.browser.stopEvent(evt);
}
case k.KEY_TAB:
if(!this.autoComplete&&this.popupWidget.isShowingNow&&this._highlighted_option){
dojo.event.browser.stopEvent(evt);
this.selectOption({"target":this._highlighted_option,"noHide":false});
this.setSelectedRange(this.textInputNode,this.textInputNode.value.length,null);
}else{
this.selectOption();
return;
}
break;
case k.KEY_SPACE:
if(this.popupWidget.isShowingNow&&this._highlighted_option){
dojo.event.browser.stopEvent(evt);
this.selectOption();
this.hideResultList();
return;
}
break;
case k.KEY_ESCAPE:
this.hideResultList();
this._prev_key_esc=true;
return;
case k.KEY_BACKSPACE:
this._prev_key_backspace=true;
if(!this.textInputNode.value.length){
this.setAllValues("","");
this.hideResultList();
_85b=false;
}
break;
case k.KEY_RIGHT_ARROW:
case k.KEY_LEFT_ARROW:
case k.KEY_SHIFT:
_85b=false;
break;
default:
if(evt.charCode==0){
_85b=false;
}
}
if(this.searchTimer){
clearTimeout(this.searchTimer);
}
if(_85b){
this.blurOptionNode();
this.searchTimer=setTimeout(dojo.lang.hitch(this,this.startSearchFromInput),this.searchDelay);
}
},onKeyDown:function(evt){
if(!document.createEvent){
this._handleKeyEvents(evt);
}
},onKeyPress:function(evt){
if(document.createEvent){
this._handleKeyEvents(evt);
}
},compositionEnd:function(evt){
this._handleKeyEvents(evt);
},onKeyUp:function(evt){
this.setValue(this.textInputNode.value);
},setSelectedValue:function(_861){
this.comboBoxSelectionValue.value=_861;
},setAllValues:function(_862,_863){
this.setValue(_862);
this.setSelectedValue(_863);
},focusOptionNode:function(node){
if(this._highlighted_option!=node){
this.blurOptionNode();
this._highlighted_option=node;
dojo.html.addClass(this._highlighted_option,"dojoComboBoxItemHighlight");
}
},blurOptionNode:function(){
if(this._highlighted_option){
dojo.html.removeClass(this._highlighted_option,"dojoComboBoxItemHighlight");
this._highlighted_option=null;
}
},highlightNextOption:function(){
if((!this._highlighted_option)||!this._highlighted_option.parentNode){
this.focusOptionNode(this.optionsListNode.firstChild);
}else{
if(this._highlighted_option.nextSibling){
this.focusOptionNode(this._highlighted_option.nextSibling);
}
}
dojo.html.scrollIntoView(this._highlighted_option);
},highlightPrevOption:function(){
if(this._highlighted_option&&this._highlighted_option.previousSibling){
this.focusOptionNode(this._highlighted_option.previousSibling);
}else{
this._highlighted_option=null;
this.hideResultList();
return;
}
dojo.html.scrollIntoView(this._highlighted_option);
},itemMouseOver:function(evt){
if(evt.target===this.optionsListNode){
return;
}
this.focusOptionNode(evt.target);
dojo.html.addClass(this._highlighted_option,"dojoComboBoxItemHighlight");
},itemMouseOut:function(evt){
if(evt.target===this.optionsListNode){
return;
}
this.blurOptionNode();
},fillInTemplate:function(args,frag){
this.comboBoxValue.name=this.name;
this.comboBoxSelectionValue.name=this.name+"_selected";
var _869=this.getFragNodeRef(frag);
dojo.html.copyStyle(this.domNode,_869);
var _86a;
if(this.mode=="remote"){
_86a=dojo.widget.incrementalComboBoxDataProvider;
}else{
if(typeof this.dataProviderClass=="string"){
_86a=dojo.evalObjPath(this.dataProviderClass);
}else{
_86a=this.dataProviderClass;
}
}
this.dataProvider=new _86a();
this.dataProvider.init(this,this.getFragNodeRef(frag));
this.popupWidget=new dojo.widget.createWidget("PopupContainer",{toggle:this.dropdownToggle,toggleDuration:this.toggleDuration});
dojo.event.connect(this,"destroy",this.popupWidget,"destroy");
this.optionsListNode=this.popupWidget.domNode;
this.domNode.appendChild(this.optionsListNode);
dojo.html.addClass(this.optionsListNode,"dojoComboBoxOptions");
dojo.event.connect(this.optionsListNode,"onclick",this,"selectOption");
dojo.event.connect(this.optionsListNode,"onmouseover",this,"_onMouseOver");
dojo.event.connect(this.optionsListNode,"onmouseout",this,"_onMouseOut");
dojo.event.connect(this.optionsListNode,"onmouseover",this,"itemMouseOver");
dojo.event.connect(this.optionsListNode,"onmouseout",this,"itemMouseOut");
},focus:function(){
this.tryFocus();
},openResultList:function(_86b){
this.clearResultList();
if(!_86b.length){
this.hideResultList();
}
if((this.autoComplete)&&(_86b.length)&&(!this._prev_key_backspace)&&(this.textInputNode.value.length>0)){
var cpos=this.getCaretPos(this.textInputNode);
if((cpos+1)>this.textInputNode.value.length){
this.textInputNode.value+=_86b[0][0].substr(cpos);
this.setSelectedRange(this.textInputNode,cpos,this.textInputNode.value.length);
}
}
var even=true;
while(_86b.length){
var tr=_86b.shift();
if(tr){
var td=document.createElement("div");
td.appendChild(document.createTextNode(tr[0]));
td.setAttribute("resultName",tr[0]);
td.setAttribute("resultValue",tr[1]);
td.className="dojoComboBoxItem "+((even)?"dojoComboBoxItemEven":"dojoComboBoxItemOdd");
even=(!even);
this.optionsListNode.appendChild(td);
}
}
this.showResultList();
},onFocusInput:function(){
this._hasFocus=true;
},onBlurInput:function(){
this._hasFocus=false;
this._handleBlurTimer(true,500);
},_handleBlurTimer:function(_870,_871){
if(this.blurTimer&&(_870||_871)){
clearTimeout(this.blurTimer);
}
if(_871){
this.blurTimer=dojo.lang.setTimeout(this,"checkBlurred",_871);
}
},_onMouseOver:function(evt){
if(!this._mouseover_list){
this._handleBlurTimer(true,0);
this._mouseover_list=true;
}
},_onMouseOut:function(evt){
var _874=evt.relatedTarget;
if(!_874||_874.parentNode!=this.optionsListNode){
this._mouseover_list=false;
this._handleBlurTimer(true,100);
this.tryFocus();
}
},_isInputEqualToResult:function(_875){
var _876=this.textInputNode.value;
if(!this.dataProvider.caseSensitive){
_876=_876.toLowerCase();
_875=_875.toLowerCase();
}
return (_876==_875);
},_isValidOption:function(){
var tgt=dojo.html.firstElement(this.optionsListNode);
var _878=false;
var tgt=dojo.html.firstElement(this.optionsListNode);
var _878=false;
while(!_878&&tgt){
if(this._isInputEqualToResult(tgt.getAttribute("resultName"))){
_878=true;
}else{
tgt=dojo.html.nextElement(tgt);
}
}
return _878;
},checkBlurred:function(){
if(!this._hasFocus&&!this._mouseover_list){
this.hideResultList();
if(!this.textInputNode.value.length){
this.setAllValues("","");
return;
}
var _879=this._isValidOption();
if(this.forceValidOption&&!_879){
this.setAllValues("","");
return;
}
if(!_879){
this.setSelectedValue("");
}
}
},sizeBackgroundIframe:function(){
var mb=dojo.html.getMarginBox(this.optionsListNode);
if(mb.width==0||mb.height==0){
dojo.lang.setTimeout(this,"sizeBackgroundIframe",100);
return;
}
},selectOption:function(evt){
var tgt=null;
if(!evt){
evt={target:this._highlighted_option};
}
if(!dojo.html.isDescendantOf(evt.target,this.optionsListNode)){
if(!this.textInputNode.value.length){
return;
}
tgt=dojo.html.firstElement(this.optionsListNode);
if(!tgt||!this._isInputEqualToResult(tgt.getAttribute("resultName"))){
return;
}
}else{
tgt=evt.target;
}
while((tgt.nodeType!=1)||(!tgt.getAttribute("resultName"))){
tgt=tgt.parentNode;
if(tgt===dojo.body()){
return false;
}
}
this.textInputNode.value=tgt.getAttribute("resultName");
this.selectedResult=[tgt.getAttribute("resultName"),tgt.getAttribute("resultValue")];
this.setAllValues(tgt.getAttribute("resultName"),tgt.getAttribute("resultValue"));
if(!evt.noHide){
this.hideResultList();
this.setSelectedRange(this.textInputNode,0,null);
}
this.tryFocus();
},clearResultList:function(){
this.optionsListNode.innerHTML="";
},hideResultList:function(){
this.popupWidget.close();
},showResultList:function(){
var _87d=this.optionsListNode.childNodes;
if(_87d.length){
var _87e=this.maxListLength;
if(_87d.length<_87e){
_87e=_87d.length;
}
with(this.optionsListNode.style){
if(_87e==_87d.length){
height="";
}else{
display="";
height=_87e*dojo.html.getMarginBox(_87d[0]).height+"px";
display="none";
}
width=(dojo.html.getMarginBox(this.domNode).width-2)+"px";
}
this.popupWidget.open(this.cbTableNode,this,this.downArrowNode);
}else{
this.hideResultList();
}
},handleArrowClick:function(){
this._handleBlurTimer(true,0);
this.tryFocus();
if(this.popupWidget.isShowingNow){
this.hideResultList();
}else{
this.startSearch("");
}
},tryFocus:function(){
try{
this.textInputNode.focus();
}
catch(e){
}
},startSearchFromInput:function(){
this.startSearch(this.textInputNode.value);
},postCreate:function(){
dojo.event.connect(this,"startSearch",this.dataProvider,"startSearch");
dojo.event.connect(this.dataProvider,"provideSearchResults",this,"openResultList");
dojo.event.connect(this.textInputNode,"onblur",this,"onBlurInput");
dojo.event.connect(this.textInputNode,"onfocus",this,"onFocusInput");
var s=dojo.widget.html.stabile.getState(this.widgetId);
if(s){
this.setState(s);
}
}});
dojo.provide("dojo.widget.ContentPane");
dojo.widget.defineWidget("dojo.widget.ContentPane",dojo.widget.HtmlWidget,{isContainer:true,adjustPaths:true,href:"",extractContent:true,parseContent:true,cacheContent:true,preventCache:null,useCache:null,preload:false,refreshOnShow:false,handler:"",executeScripts:false,initializer:function(){
this._styleNodes=[];
this._onLoadStack=[];
this._onUnLoadStack=[];
this._callOnUnLoad=false;
this.scriptScope;
this._ioBindObj;
},postCreate:function(args,frag,_882){
if(this.handler!==""){
this.setHandler(this.handler);
}
if(this.isShowing()||this.preload){
this.loadContents();
}
},show:function(){
if(this.refreshOnShow){
this.refresh();
}else{
this.loadContents();
}
dojo.widget.ContentPane.superclass.show.call(this);
},refresh:function(){
this.isLoaded=false;
this.loadContents();
},loadContents:function(){
if(this.isLoaded){
return;
}
this.isLoaded=true;
if(dojo.lang.isFunction(this.handler)){
this._runHandler();
}else{
if(this.href!=""){
this._downloadExternalContent(this.href,this.cacheContent);
}
}
},setUrl:function(url){
this.href=url;
this.isLoaded=false;
if(this.preload||this.isShowing()){
this.loadContents();
}
},abort:function(){
var bind=this._ioBindObj;
if(!bind||!bind.abort){
return;
}
bind.abort();
delete this._ioBindObj;
},_downloadExternalContent:function(url,_886){
this.abort();
this._handleDefaults("Loading...","onDownloadStart");
var self=this;
this._ioBindObj=dojo.io.bind(this._cacheSetting({url:url,mimetype:"text/html",load:function(type,data,xhr){
self.onDownloadEnd.call(self,url,data);
},error:function(type,err,xhr){
var e={responseText:xhr.responseText,status:xhr.status,statusText:xhr.statusText,responseHeaders:xhr.getAllResponseHeaders(),_text:"Error loading '"+url+"' ("+xhr.status+" "+xhr.statusText+")"};
self._handleDefaults.call(self,e,"onDownloadError");
self.onLoad();
}},_886));
},_cacheSetting:function(_88f,_890){
_88f.preventCache=((typeof this.preventCache!="null")?this.preventCache:!_890);
_88f.useCache=(typeof this.useCache!="null")?this.useCache:_890;
return _88f;
},onLoad:function(e){
this._runStack("_onLoadStack");
},onUnLoad:function(e){
this._runStack("_onUnLoadStack");
delete this.scriptScope;
},_runStack:function(_893){
var st=this[_893];
var err="";
var _896=this.scriptScope||window;
for(var i=0;i<st.length;i++){
try{
st[i].call(_896);
}
catch(e){
err+="\n"+st[i]+" failed: "+e.description;
}
}
this[_893]=[];
if(err.length){
var name=(_893=="_onLoadStack")?"addOnLoad":"addOnUnLoad";
this._handleDefaults(name+" failure\n "+err,"onExecError",true);
}
},addOnLoad:function(obj,func){
this._pushOnStack(this._onLoadStack,obj,func);
},addOnUnLoad:function(obj,func){
this._pushOnStack(this._onUnLoadStack,obj,func);
},_pushOnStack:function(_89d,obj,func){
if(typeof func=="undefined"){
_89d.push(obj);
}else{
_89d.push(function(){
obj[func]();
});
}
},destroy:function(){
this.onUnLoad();
dojo.widget.ContentPane.superclass.destroy.call(this);
},onExecError:function(e){
},onContentError:function(e){
},onDownloadError:function(e){
},onDownloadStart:function(e){
},onDownloadEnd:function(url,data){
data=this.splitAndFixPaths(data,url);
this.setContent(data);
},_handleDefaults:function(e,_8a7,_8a8){
if(!_8a7){
_8a7="onContentError";
}
if(dojo.lang.isString(e)){
e={_text:e};
}
if(!e._text){
e._text=e.toString();
}
e.toString=function(){
return this._text;
};
if(typeof e.returnValue!="boolean"){
e.returnValue=true;
}
if(typeof e.preventDefault!="function"){
e.preventDefault=function(){
this.returnValue=false;
};
}
this[_8a7](e);
if(e.returnValue){
if(_8a8){
alert(e.toString());
}else{
if(this._callOnUnLoad){
this.onUnLoad();
}
this._callOnUnLoad=false;
this._setContent(e.toString());
}
}
},splitAndFixPaths:function(s,url){
var _8ab=[],scripts=[],tmp=[];
var _8ac=[],requires=[],attr=[],styles=[];
var str="",path="",fix="",tagFix="",tag="",origPath="";
if(!url){
url="./";
}
if(s){
var _8ae=/<title[^>]*>([\s\S]*?)<\/title>/i;
while(_8ac=_8ae.exec(s)){
_8ab.push(_8ac[1]);
s=s.substring(0,_8ac.index)+s.substr(_8ac.index+_8ac[0].length);
}
if(this.adjustPaths){
var _8af=/<[a-z][a-z0-9]*[^>]*\s(?:(?:src|href|style)=[^>])+[^>]*>/i;
var _8b0=/\s(src|href|style)=(['"]?)([\w()\[\]\/.,\\'"-:;#=&?\s@]+?)\2/i;
var _8b1=/^(?:[#]|(?:(?:https?|ftps?|file|javascript|mailto|news):))/;
while(tag=_8af.exec(s)){
str+=s.substring(0,tag.index);
s=s.substring((tag.index+tag[0].length),s.length);
tag=tag[0];
tagFix="";
while(attr=_8b0.exec(tag)){
path="";
origPath=attr[3];
switch(attr[1].toLowerCase()){
case "src":
case "href":
if(_8b1.exec(origPath)){
path=origPath;
}else{
path=(new dojo.uri.Uri(url,origPath).toString());
}
break;
case "style":
path=dojo.html.fixPathsInCssText(origPath,url);
break;
default:
path=origPath;
}
fix=" "+attr[1]+"="+attr[2]+path+attr[2];
tagFix+=tag.substring(0,attr.index)+fix;
tag=tag.substring((attr.index+attr[0].length),tag.length);
}
str+=tagFix+tag;
}
s=str+s;
}
_8ae=/(?:<(style)[^>]*>([\s\S]*?)<\/style>|<link ([^>]*rel=['"]?stylesheet['"]?[^>]*)>)/i;
while(_8ac=_8ae.exec(s)){
if(_8ac[1]&&_8ac[1].toLowerCase()=="style"){
styles.push(dojo.html.fixPathsInCssText(_8ac[2],url));
}else{
if(attr=_8ac[3].match(/href=(['"]?)([^'">]*)\1/i)){
styles.push({path:attr[2]});
}
}
s=s.substring(0,_8ac.index)+s.substr(_8ac.index+_8ac[0].length);
}
var _8ae=/<script([^>]*)>([\s\S]*?)<\/script>/i;
var _8b2=/src=(['"]?)([^"']*)\1/i;
var _8b3=/.*(\bdojo\b\.js(?:\.uncompressed\.js)?)$/;
var _8b4=/(?:var )?\bdjConfig\b(?:[\s]*=[\s]*\{[^}]+\}|\.[\w]*[\s]*=[\s]*[^;\n]*)?;?|dojo\.hostenv\.writeIncludes\(\s*\);?/g;
var _8b5=/dojo\.(?:(?:require(?:After)?(?:If)?)|(?:widget\.(?:manager\.)?registerWidgetPackage)|(?:(?:hostenv\.)?setModulePrefix)|defineNamespace)\((['"]).*?\1\)\s*;?/;
while(_8ac=_8ae.exec(s)){
if(this.executeScripts&&_8ac[1]){
if(attr=_8b2.exec(_8ac[1])){
if(_8b3.exec(attr[2])){
dojo.debug("Security note! inhibit:"+attr[2]+" from  beeing loaded again.");
}else{
scripts.push({path:attr[2]});
}
}
}
if(_8ac[2]){
var sc=_8ac[2].replace(_8b4,"");
if(!sc){
continue;
}
while(tmp=_8b5.exec(sc)){
requires.push(tmp[0]);
sc=sc.substring(0,tmp.index)+sc.substr(tmp.index+tmp[0].length);
}
if(this.executeScripts){
scripts.push(sc);
}
}
s=s.substr(0,_8ac.index)+s.substr(_8ac.index+_8ac[0].length);
}
if(this.extractContent){
_8ac=s.match(/<body[^>]*>\s*([\s\S]+)\s*<\/body>/im);
if(_8ac){
s=_8ac[1];
}
}
if(this.executeScripts){
var _8ae=/(<[a-zA-Z][a-zA-Z0-9]*\s[^>]*\S=(['"])[^>]*[^\.\]])scriptScope([^>]*>)/;
str="";
while(tag=_8ae.exec(s)){
tmp=((tag[2]=="'")?"\"":"'");
str+=s.substring(0,tag.index);
s=s.substr(tag.index).replace(_8ae,"$1dojo.widget.byId("+tmp+this.widgetId+tmp+").scriptScope$3");
}
s=str+s;
}
}
return {"xml":s,"styles":styles,"titles":_8ab,"requires":requires,"scripts":scripts,"url":url};
},_setContent:function(cont){
this.destroyChildren();
for(var i=0;i<this._styleNodes.length;i++){
if(this._styleNodes[i]&&this._styleNodes[i].parentNode){
this._styleNodes[i].parentNode.removeChild(this._styleNodes[i]);
}
}
this._styleNodes=[];
var node=this.containerNode||this.domNode;
while(node.firstChild){
try{
dojo.event.browser.clean(node.firstChild);
}
catch(e){
}
node.removeChild(node.firstChild);
}
try{
if(typeof cont!="string"){
node.innerHTML="";
node.appendChild(cont);
}else{
node.innerHTML=cont;
}
}
catch(e){
e._text="Could'nt load content:"+e.description;
this._handleDefaults(e,"onContentError");
}
},setContent:function(data){
this.abort();
if(this._callOnUnLoad){
this.onUnLoad();
}
this._callOnUnLoad=true;
if(!data||dojo.html.isNode(data)){
this._setContent(data);
this.onResized();
this.onLoad();
}else{
if(!data.xml){
this.href="";
data=this.splitAndFixPaths(data);
}
this._setContent(data.xml);
for(var i=0;i<data.styles.length;i++){
if(data.styles[i].path){
this._styleNodes.push(dojo.html.insertCssFile(data.styles[i].path));
}else{
this._styleNodes.push(dojo.html.insertCssText(data.styles[i]));
}
}
if(this.parseContent){
for(var i=0;i<data.requires.length;i++){
try{
eval(data.requires[i]);
}
catch(e){
e._text="Error in packageloading calls, "+e.description;
this._handleDefaults(e,"onContentError",true);
}
}
}
var _8bc=this;
function asyncParse(){
if(_8bc.executeScripts){
_8bc._executeScripts(data.scripts);
}
if(_8bc.parseContent){
var node=_8bc.containerNode||_8bc.domNode;
var _8be=new dojo.xml.Parse();
var frag=_8be.parseElement(node,null,true);
dojo.widget.getParser().createSubComponents(frag,_8bc);
}
_8bc.onResized();
_8bc.onLoad();
}
if(dojo.hostenv.isXDomain&&data.requires.length){
dojo.addOnLoad(asyncParse);
}else{
asyncParse();
}
}
},setHandler:function(_8c0){
var fcn=dojo.lang.isFunction(_8c0)?_8c0:window[_8c0];
if(!dojo.lang.isFunction(fcn)){
this._handleDefaults("Unable to set handler, '"+_8c0+"' not a function.","onExecError",true);
return;
}
this.handler=function(){
return fcn.apply(this,arguments);
};
},_runHandler:function(){
if(dojo.lang.isFunction(this.handler)){
this.handler(this,this.domNode);
return false;
}
return true;
},_executeScripts:function(_8c2){
var self=this;
var tmp="",code="";
for(var i=0;i<_8c2.length;i++){
if(_8c2[i].path){
dojo.io.bind(this._cacheSetting({"url":_8c2[i].path,"load":function(type,_8c7){
dojo.lang.hitch(self,tmp=_8c7);
},"error":function(type,_8c9){
_8c9._text=type+" downloading remote script";
self._handleDefaults.call(self,_8c9,"onExecError",true);
},"mimetype":"text/plain","sync":true},this.cacheContent));
code+=tmp;
}else{
code+=_8c2[i];
}
}
try{
delete this.scriptScope;
this.scriptScope=new (new Function("_container_",code+"; return this;"))(self);
}
catch(e){
e._text="Error running scripts from content:\n"+e.description;
this._handleDefaults(e,"onExecError",true);
}
}});
dojo.provide("dojo.widget.SplitContainer");
dojo.provide("dojo.widget.SplitContainerPanel");
dojo.widget.defineWidget("dojo.widget.SplitContainer",dojo.widget.HtmlWidget,{initializer:function(){
this.sizers=[];
},isContainer:true,virtualSizer:null,isHorizontal:0,paneBefore:null,paneAfter:null,isSizing:false,dragOffset:null,startPoint:null,lastPoint:null,sizingSplitter:null,isActiveResize:0,offsetX:0,offsetY:0,isDraggingLeft:0,templateCssString:".dojoSplitContainer{\n	position: relative;\n	overflow: hidden;\n}\n\n.dojoSplitPane{\n	position: absolute;\n}\n\n.dojoSplitContainerSizerH,\n.dojoSplitContainerSizerV {\n	font-size: 1px;\n	cursor: move;\n	cursor: w-resize;\n	background-color: ThreeDFace;\n	border: 1px solid;\n	border-color: ThreeDHighlight ThreeDShadow ThreeDShadow ThreeDHighlight;\n	margin: 0;\n}\n\n.dojoSplitContainerSizerV {\n	cursor: n-resize;\n}\n\n.dojoSplitContainerVirtualSizerH,\n.dojoSplitContainerVirtualSizerV {\n	font-size: 1px;\n	cursor: move;\n	cursor: w-resize;\n	background-color: ThreeDShadow;\n	-moz-opacity: 0.5;\n	opacity: 0.5;\n	filter: Alpha(Opacity=50);\n	margin: 0;\n}\n\n.dojoSplitContainerVirtualSizerV {\n	cursor: n-resize;\n}\n",templateCssPath:dojo.uri.dojoUri("src/widget/templates/HtmlSplitContainer.css"),originPos:null,persist:true,activeSizing:"",sizerWidth:15,orientation:"horizontal",debugName:"",fillInTemplate:function(){
dojo.html.insertCssFile(this.templateCssPath,null,true);
dojo.html.addClass(this.domNode,"dojoSplitContainer");
this.domNode.style.overflow="hidden";
var _8ca=dojo.html.getContentBox(this.domNode);
this.paneWidth=_8ca.width;
this.paneHeight=_8ca.height;
this.isHorizontal=(this.orientation=="horizontal")?1:0;
this.isActiveResize=(this.activeSizing=="1")?1:0;
},onResized:function(e){
var _8cc=dojo.html.getContentBox(this.domNode);
this.paneWidth=_8cc.width;
this.paneHeight=_8cc.height;
this.layoutPanels();
},postCreate:function(args,_8ce,_8cf){
for(var i=0;i<this.children.length;i++){
with(this.children[i].domNode.style){
position="absolute";
}
dojo.html.addClass(this.children[i].domNode,"dojoSplitPane");
if(i==this.children.length-1){
break;
}
this._addSizer();
}
this.virtualSizer=document.createElement("div");
this.virtualSizer.style.position="absolute";
this.virtualSizer.style.display="none";
this.virtualSizer.style.zIndex=10;
this.virtualSizer.className=this.isHorizontal?"dojoSplitContainerVirtualSizerH":"dojoSplitContainerVirtualSizerV";
this.domNode.appendChild(this.virtualSizer);
dojo.html.disableSelection(this.virtualSizer);
if(this.persist){
this.restoreState();
}
this.resizeSoon();
},_injectChild:function(_8d1){
with(_8d1.domNode.style){
position="absolute";
}
dojo.html.addClass(_8d1.domNode,"dojoSplitPane");
},_addSizer:function(){
var i=this.sizers.length;
this.sizers[i]=document.createElement("div");
this.sizers[i].style.position="absolute";
this.sizers[i].className=this.isHorizontal?"dojoSplitContainerSizerH":"dojoSplitContainerSizerV";
var self=this;
var _8d4=(function(){
var _8d5=i;
return function(e){
self.beginSizing(e,_8d5);
};
})();
dojo.event.connect(this.sizers[i],"onmousedown",_8d4);
this.domNode.appendChild(this.sizers[i]);
dojo.html.disableSelection(this.sizers[i]);
},removeChild:function(_8d7){
if(this.sizers.length>0){
for(var x=0;x<this.children.length;x++){
if(this.children[x]===_8d7){
var i=this.sizers.length-1;
this.domNode.removeChild(this.sizers[i]);
this.sizers.length=i;
break;
}
}
}
dojo.widget.SplitContainer.superclass.removeChild.call(this,_8d7,arguments);
this.onResized();
},addChild:function(_8da,_8db,pos,ref,_8de){
dojo.widget.SplitContainer.superclass.addChild.call(this,_8da,_8db,pos,ref,_8de);
this._injectChild(_8da);
if(this.children.length>1){
this._addSizer();
}
this.layoutPanels();
},layoutPanels:function(){
if(this.children.length==0){
return;
}
var _8df=this.isHorizontal?this.paneWidth:this.paneHeight;
if(this.children.length>1){
_8df-=this.sizerWidth*(this.children.length-1);
}
var _8e0=0;
for(var i=0;i<this.children.length;i++){
_8e0+=this.children[i].sizeShare;
}
var _8e2=_8df/_8e0;
var _8e3=0;
for(var i=0;i<this.children.length-1;i++){
var size=Math.round(_8e2*this.children[i].sizeShare);
this.children[i].sizeActual=size;
_8e3+=size;
}
this.children[this.children.length-1].sizeActual=_8df-_8e3;
this.checkSizes();
var pos=0;
var size=this.children[0].sizeActual;
this.movePanel(this.children[0].domNode,pos,size);
this.children[0].position=pos;
this.children[0].checkSize();
pos+=size;
for(var i=1;i<this.children.length;i++){
this.movePanel(this.sizers[i-1],pos,this.sizerWidth);
this.sizers[i-1].position=pos;
pos+=this.sizerWidth;
size=this.children[i].sizeActual;
this.movePanel(this.children[i].domNode,pos,size);
this.children[i].position=pos;
this.children[i].checkSize();
pos+=size;
}
},movePanel:function(_8e6,pos,size){
if(this.isHorizontal){
_8e6.style.left=pos+"px";
_8e6.style.top=0;
dojo.html.setMarginBox(_8e6,{width:size,height:this.paneHeight});
}else{
_8e6.style.left=0;
_8e6.style.top=pos+"px";
dojo.html.setMarginBox(_8e6,{width:this.paneWidth,height:size});
}
},growPane:function(_8e9,pane){
if(_8e9>0){
if(pane.sizeActual>pane.sizeMin){
if((pane.sizeActual-pane.sizeMin)>_8e9){
pane.sizeActual=pane.sizeActual-_8e9;
_8e9=0;
}else{
_8e9-=pane.sizeActual-pane.sizeMin;
pane.sizeActual=pane.sizeMin;
}
}
}
return _8e9;
},checkSizes:function(){
var _8eb=0;
var _8ec=0;
for(var i=0;i<this.children.length;i++){
_8ec+=this.children[i].sizeActual;
_8eb+=this.children[i].sizeMin;
}
if(_8eb<=_8ec){
var _8ee=0;
for(var i=0;i<this.children.length;i++){
if(this.children[i].sizeActual<this.children[i].sizeMin){
_8ee+=this.children[i].sizeMin-this.children[i].sizeActual;
this.children[i].sizeActual=this.children[i].sizeMin;
}
}
if(_8ee>0){
if(this.isDraggingLeft){
for(var i=this.children.length-1;i>=0;i--){
_8ee=this.growPane(_8ee,this.children[i]);
}
}else{
for(var i=0;i<this.children.length;i++){
_8ee=this.growPane(_8ee,this.children[i]);
}
}
}
}else{
for(var i=0;i<this.children.length;i++){
this.children[i].sizeActual=Math.round(_8ec*(this.children[i].sizeMin/_8eb));
}
}
},beginSizing:function(e,i){
var _8f1=e.layerX;
var _8f2=e.layerY;
var _8f3=e.pageX;
var _8f4=e.pageY;
this.paneBefore=this.children[i];
this.paneAfter=this.children[i+1];
this.isSizing=true;
this.sizingSplitter=this.sizers[i];
this.originPos=dojo.html.getAbsolutePosition(this.domNode,true);
this.dragOffset={"x":_8f1,"y":_8f2};
this.startPoint={"x":_8f3,"y":_8f4};
this.lastPoint={"x":_8f3,"y":_8f4};
this.offsetX=_8f3-_8f1;
this.offsetY=_8f4-_8f2;
if(!this.isActiveResize){
this.showSizingLine();
}
dojo.event.connect(document.documentElement,"onmousemove",this,"changeSizing");
dojo.event.connect(document.documentElement,"onmouseup",this,"endSizing");
},changeSizing:function(e){
var _8f6=e.pageX;
var _8f7=e.pageY;
if(this.isActiveResize){
this.lastPoint={"x":_8f6,"y":_8f7};
this.movePoint();
this.updateSize();
}else{
this.lastPoint={"x":_8f6,"y":_8f7};
this.movePoint();
this.moveSizingLine();
}
},endSizing:function(e){
if(!this.isActiveResize){
this.hideSizingLine();
}
this.updateSize();
this.isSizing=false;
dojo.event.disconnect(document.documentElement,"onmousemove",this,"changeSizing");
dojo.event.disconnect(document.documentElement,"onmouseup",this,"endSizing");
if(this.persist){
this.saveState(this);
}
},movePoint:function(){
var p=this.screenToMainClient(this.lastPoint);
if(this.isHorizontal){
var a=p.x-this.dragOffset.x;
a=this.legaliseSplitPoint(a);
p.x=a+this.dragOffset.x;
}else{
var a=p.y-this.dragOffset.y;
a=this.legaliseSplitPoint(a);
p.y=a+this.dragOffset.y;
}
this.lastPoint=this.mainClientToScreen(p);
},screenToClient:function(pt){
pt.x-=(this.offsetX+this.sizingSplitter.position);
pt.y-=(this.offsetY+this.sizingSplitter.position);
return pt;
},clientToScreen:function(pt){
pt.x+=(this.offsetX+this.sizingSplitter.position);
pt.y+=(this.offsetY+this.sizingSplitter.position);
return pt;
},screenToMainClient:function(pt){
pt.x-=this.offsetX;
pt.y-=this.offsetY;
return pt;
},mainClientToScreen:function(pt){
pt.x+=this.offsetX;
pt.y+=this.offsetY;
return pt;
},legaliseSplitPoint:function(a){
a+=this.sizingSplitter.position;
this.isDraggingLeft=(a>0)?1:0;
if(!this.isActiveResize){
if(a<this.paneBefore.position+this.paneBefore.sizeMin){
a=this.paneBefore.position+this.paneBefore.sizeMin;
}
if(a>this.paneAfter.position+(this.paneAfter.sizeActual-(this.sizerWidth+this.paneAfter.sizeMin))){
a=this.paneAfter.position+(this.paneAfter.sizeActual-(this.sizerWidth+this.paneAfter.sizeMin));
}
}
a-=this.sizingSplitter.position;
this.checkSizes();
return a;
},updateSize:function(){
var p=this.clientToScreen(this.lastPoint);
var p=this.screenToClient(this.lastPoint);
var pos=this.isHorizontal?p.x-(this.dragOffset.x+this.originPos.x):p.y-(this.dragOffset.y+this.originPos.y);
var _902=this.paneBefore.position;
var _903=this.paneAfter.position+this.paneAfter.sizeActual;
this.paneBefore.sizeActual=pos-_902;
this.paneAfter.position=pos+this.sizerWidth;
this.paneAfter.sizeActual=_903-this.paneAfter.position;
for(var i=0;i<this.children.length;i++){
this.children[i].sizeShare=this.children[i].sizeActual;
}
this.layoutPanels();
},showSizingLine:function(){
this.moveSizingLine();
if(this.isHorizontal){
dojo.html.setMarginBox(this.virtualSizer,{width:this.sizerWidth,height:this.paneHeight});
}else{
dojo.html.setMarginBox(this.virtualSizer,{width:this.paneWidth,height:this.sizerWidth});
}
this.virtualSizer.style.display="block";
},hideSizingLine:function(){
this.virtualSizer.style.display="none";
},moveSizingLine:function(){
var _905={"x":0,"y":0};
if(this.isHorizontal){
_905.x+=(this.lastPoint.x-this.startPoint.x)+this.sizingSplitter.position;
}else{
_905.y+=(this.lastPoint.y-this.startPoint.y)+this.sizingSplitter.position;
}
this.virtualSizer.style.left=_905.x+"px";
this.virtualSizer.style.top=_905.y+"px";
},_getCookieName:function(i){
return this.widgetId+"_"+i;
},restoreState:function(){
for(var i=0;i<this.children.length;i++){
var _908=this._getCookieName(i);
var _909=dojo.io.cookie.getCookie(_908);
if(_909!=null){
var pos=parseInt(_909);
this.children[i].sizeShare=pos;
}
}
},saveState:function(){
for(var i=0;i<this.children.length;i++){
var _90c=this._getCookieName(i);
dojo.io.cookie.setCookie(_90c,this.children[i].sizeShare,null,null,null,null);
}
}});
dojo.lang.extend(dojo.widget.Widget,{sizeMin:10,sizeShare:10});
dojo.widget.defineWidget("dojo.widget.SplitContainerPanel",dojo.widget.ContentPane,{});
dojo.provide("dojo.widget.html.layout");
dojo.widget.html.layout=function(_90d,_90e,_90f){
dojo.html.addClass(_90d,"dojoLayoutContainer");
_90e=dojo.lang.filter(_90e,function(_910,idx){
_910.idx=idx;
return dojo.lang.inArray(["top","bottom","left","right","client","flood"],_910.layoutAlign);
});
if(_90f&&_90f!="none"){
var rank=function(_913){
switch(_913.layoutAlign){
case "flood":
return 1;
case "left":
case "right":
return (_90f=="left-right")?2:3;
case "top":
case "bottom":
return (_90f=="left-right")?3:2;
default:
return 4;
}
};
_90e.sort(function(a,b){
return (rank(a)-rank(b))||(a.idx-b.idx);
});
}
var f={top:dojo.html.getPixelValue(_90d,"padding-top",true),left:dojo.html.getPixelValue(_90d,"padding-left",true)};
dojo.lang.mixin(f,dojo.html.getContentBox(_90d));
dojo.lang.forEach(_90e,function(_917){
var elm=_917.domNode;
var pos=_917.layoutAlign;
with(elm.style){
left=f.left+"px";
top=f.top+"px";
bottom="auto";
right="auto";
}
dojo.html.addClass(elm,"dojoAlign"+dojo.string.capitalize(pos));
if((pos=="top")||(pos=="bottom")){
dojo.html.setMarginBox(elm,{width:f.width});
var h=dojo.html.getMarginBox(elm).height;
f.height-=h;
if(pos=="top"){
f.top+=h;
}else{
elm.style.top=f.top+f.height+"px";
}
}else{
if(pos=="left"||pos=="right"){
dojo.html.setMarginBox(elm,{height:f.height});
var w=dojo.html.getMarginBox(elm).width;
f.width-=w;
if(pos=="left"){
f.left+=w;
}else{
elm.style.left=f.left+f.width+"px";
}
}else{
if(pos=="flood"||pos=="client"){
dojo.html.setMarginBox(elm,{width:f.width,height:f.height});
}
}
}
if(_917.onResized){
_917.onResized();
}
});
};
dojo.html.insertCssText(".dojoLayoutContainer{ position: relative; display: block; }\n"+"body .dojoAlignTop, body .dojoAlignBottom, body .dojoAlignLeft, body .dojoAlignRight { position: absolute; overflow: hidden; }\n"+"body .dojoAlignClient { position: absolute }\n"+".dojoAlignClient { overflow: auto; }\n");
dojo.provide("dojo.widget.TabContainer");
dojo.widget.defineWidget("dojo.widget.TabContainer",dojo.widget.HtmlWidget,{isContainer:true,labelPosition:"top",closeButton:"none",useVisibility:false,doLayout:true,templateString:"<div id=\"${this.widgetId}\" class=\"dojoTabContainer\" >\n	<div dojoAttachPoint=\"dojoTabLabels\" waiRole=\"tablist\"></div>\n	<div class=\"dojoTabPaneWrapper\" dojoAttachPoint=\"containerNode\" dojoAttachEvent=\"keyDown\" waiRole=\"tabpanel\"></div>\n</div>\n",templateCssString:".dojoTabContainer {\n	position : relative;\n}\n\n.dojoTabPaneWrapper {\n	position : relative;\n	border : 1px solid #6290d2;\n	clear: both;\n	_zoom: 1; /* force IE6 layout mode so top border doesnt disappear */\n}\n\n.dojoTabLabels-top {\n	position : absolute;\n	top : 0px;\n	left : 0px;\n	overflow : visible;\n	margin-bottom : -1px;\n	width : 100%;\n	z-index: 2;	/* so the bottom of the tab label will cover up the border of dojoTabPaneWrapper */\n}\n\n.dojoTabNoLayout.dojoTabLabels-top {\n	position : relative;\n}\n\n.dojoTabNoLayout.dojoTabLabels-top .dojoTabPaneTab {\n	margin-bottom: -1px;\n	_margin-bottom: 0px; /* IE filter so top border lines up correctly */\n}\n\n.dojoTabPaneTab {\n	position : relative;\n	float : left;\n	padding-left : 9px;\n	border-bottom : 1px solid #6290d2;\n	background : url(images/tab_left.gif) no-repeat left top;\n	cursor: pointer;\n	white-space: nowrap;\n	z-index: 3;\n}\n\n.dojoTabPaneTab div {\n	display : block;\n	padding : 4px 15px 4px 6px;\n	background : url(images/tab_top_right.gif) no-repeat right top;\n	color : #333;\n	font-size : 90%;\n}\n\n.dojoTabPanePaneClose {\n	position : absolute;\n	bottom : 0px;\n	right : 6px;\n	height : 12px;\n	width : 12px;\n	background : url(images/tab_close.gif) no-repeat right top;\n}\n\n.dojoTabPanePaneCloseHover {\n	background-image : url(images/tab_close_h.gif);\n}\n\n.dojoTabPaneTabClose {\n	display : inline-block;\n	height : 12px;\n	width : 12px;\n	padding : 0 12px 0 0;\n	margin : 0 -10px 0 10px;\n	background : url(images/tab_close.gif) no-repeat right top;\n	cursor : default;\n}\n\n.dojoTabPaneTabCloseHover {\n	background-image : url(images/tab_close_h.gif);\n}\n\n.dojoTabPaneTab.current {\n	padding-bottom : 1px;\n	border-bottom : 0;\n	background-position : 0 -150px;\n}\n\n.dojoTabPaneTab.current div {\n	padding-bottom : 5px;\n	margin-bottom : -1px;\n	background-position : 100% -150px;\n}\n\n/* bottom tabs */\n\n.dojoTabLabels-bottom {\n	position : absolute;\n	bottom : 0px;\n	left : 0px;\n	overflow : visible;\n	margin-top : -1px;\n	width : 100%;\n	z-index: 2;\n}\n\n.dojoTabNoLayout.dojoTabLabels-bottom {\n	position : relative;\n}\n\n.dojoTabLabels-bottom .dojoTabPaneTab {\n	border-top :  1px solid #6290d2;\n	border-bottom : 0;\n	background : url(images/tab_bot_left.gif) no-repeat left bottom;\n}\n\n.dojoTabLabels-bottom .dojoTabPaneTab div {\n	background : url(images/tab_bot_right.gif) no-repeat right bottom;\n}\n\n.dojoTabLabels-bottom .dojoTabPaneTab.current {\n	border-top : 0;\n	background : url(images/tab_bot_left_curr.gif) no-repeat left bottom;\n}\n\n.dojoTabLabels-bottom .dojoTabPaneTab.current div {\n	padding-top : 4px;\n	background : url(images/tab_bot_right_curr.gif) no-repeat right bottom;\n}\n\n/* right-h tabs */\n\n.dojoTabLabels-right-h {\n	position : absolute;\n	top : 0px;\n	right : 0px;\n	overflow : visible;\n	margin-left : -1px;\n	z-index: 2;\n}\n\n.dojoTabLabels-right-h .dojoTabPaneTab {\n	padding-left : 0;\n	border-left :  1px solid #6290d2;\n	border-bottom : 0;\n	background : url(images/tab_bot_right.gif) no-repeat right bottom;\n	float : none;\n}\n\n.dojoTabLabels-right-h .dojoTabPaneTab div {\n	padding : 4px 15px 4px 15px;\n}\n\n.dojoTabLabels-right-h .dojoTabPaneTab.current {\n	border-left :  0;\n	border-bottom :  1px solid #6290d2;\n}\n\n/* left-h tabs */\n\n.dojoTabLabels-left-h {\n	position : absolute;\n	top : 0px;\n	left : 0px;\n	overflow : visible;\n	margin-right : -1px;\n	z-index: 2;\n}\n\n.dojoTabLabels-left-h .dojoTabPaneTab {\n	border-right :  1px solid #6290d2;\n	border-bottom : 0;\n	float : none;\n	background : url(images/tab_top_left.gif) no-repeat left top;\n}\n\n.dojoTabLabels-left-h .dojoTabPaneTab.current {\n	border-right : 0;\n	border-bottom :  1px solid #6290d2;\n	padding-bottom : 0;\n	background : url(images/tab_top_left.gif) no-repeat 0 -150px;\n}\n\n.dojoTabLabels-left-h .dojoTabPaneTab div {\n	background : 0;\n	border-bottom :  1px solid #6290d2;\n}\n",templateCssPath:dojo.uri.dojoUri("src/widget/templates/HtmlTabContainer.css"),selectedTab:"",fillInTemplate:function(args,frag){
var _91e=this.getFragNodeRef(frag);
dojo.html.copyStyle(this.domNode,_91e);
dojo.widget.TabContainer.superclass.fillInTemplate.call(this,args,frag);
},postCreate:function(args,frag){
for(var i=0;i<this.children.length;i++){
this._setupTab(this.children[i]);
}
if(this.closeButton=="pane"){
var div=document.createElement("div");
dojo.html.addClass(div,"dojoTabPanePaneClose");
dojo.event.connect(div,"onclick",dojo.lang.hitch(this,function(){
this._runOnCloseTab(this.selectedTabWidget);
}));
dojo.event.connect(div,"onmouseover",function(){
dojo.html.addClass(div,"dojoTabPanePaneCloseHover");
});
dojo.event.connect(div,"onmouseout",function(){
dojo.html.removeClass(div,"dojoTabPanePaneCloseHover");
});
this.dojoTabLabels.appendChild(div);
}
if(!this.doLayout){
dojo.html.addClass(this.dojoTabLabels,"dojoTabNoLayout");
if(this.labelPosition=="bottom"){
var p=this.dojoTabLabels.parentNode;
p.removeChild(this.dojoTabLabels);
p.appendChild(this.dojoTabLabels);
}
}
dojo.html.addClass(this.dojoTabLabels,"dojoTabLabels-"+this.labelPosition);
this._doSizing();
if(this.selectedTabWidget){
this.selectTab(this.selectedTabWidget,true);
}
},addChild:function(_924,_925,pos,ref,_928){
this._setupTab(_924);
dojo.widget.TabContainer.superclass.addChild.call(this,_924,_925,pos,ref,_928);
this._doSizing();
},_setupTab:function(tab){
tab.domNode.style.display="none";
tab.div=document.createElement("div");
dojo.html.addClass(tab.div,"dojoTabPaneTab");
var _92a=document.createElement("div");
var _92b=document.createElement("span");
_92b.innerHTML=tab.label;
_92b.tabIndex="-1";
dojo.widget.wai.setAttr(_92b,"waiRole","role","tab");
_92a.appendChild(_92b);
dojo.html.disableSelection(_92b);
if(this.closeButton=="tab"||tab.tabCloseButton){
var img=document.createElement("span");
dojo.html.addClass(img,"dojoTabPaneTabClose");
dojo.event.connect(img,"onclick",dojo.lang.hitch(this,function(evt){
this._runOnCloseTab(tab);
dojo.event.browser.stopEvent(evt);
}));
dojo.event.connect(img,"onmouseover",function(){
dojo.html.addClass(img,"dojoTabPaneTabCloseHover");
});
dojo.event.connect(img,"onmouseout",function(){
dojo.html.removeClass(img,"dojoTabPaneTabCloseHover");
});
_92a.appendChild(img);
}
tab.div.appendChild(_92a);
tab.div.tabTitle=_92b;
this.dojoTabLabels.appendChild(tab.div);
dojo.event.connect(tab.div,"onclick",dojo.lang.hitch(this,function(){
this.selectTab(tab);
}));
dojo.event.connect(tab.div,"onkeydown",dojo.lang.hitch(this,function(evt){
this.tabNavigation(evt,tab);
}));
if(!this.selectedTabWidget||this.selectedTab==tab.widgetId||tab.selected||(this.children.length==0)){
if(this.selectedTabWidget){
this._hideTab(this.selectedTabWidget);
}
this.selectedTabWidget=tab;
this._showTab(tab);
}else{
this._hideTab(tab);
}
dojo.html.addClass(tab.domNode,"dojoTabPane");
if(this.doLayout){
with(tab.domNode.style){
top=dojo.html.getPixelValue(this.containerNode,"padding-top",true);
left=dojo.html.getPixelValue(this.containerNode,"padding-left",true);
}
}
},_doSizing:function(){
if(!this.doLayout){
return;
}
var _92f=this.labelPosition.replace(/-h/,"");
var _930=[{domNode:this.dojoTabLabels,layoutAlign:_92f},{domNode:this.containerNode,layoutAlign:"client"}];
dojo.widget.html.layout(this.domNode,_930);
var _931=dojo.html.getContentBox(this.containerNode);
dojo.lang.forEach(this.children,function(_932){
if(_932.selected){
_932.resizeTo(_931.width,_931.height);
}
});
},removeChild:function(tab){
dojo.event.disconnect(tab.div,"onclick",function(){
});
if(this.closeButton=="tab"){
var img=tab.div.lastChild.lastChild;
if(img){
dojo.html.removeClass(img,"dojoTabPaneTabClose");
}
}
dojo.widget.TabContainer.superclass.removeChild.call(this,tab);
dojo.html.removeClass(tab.domNode,"dojoTabPane");
this.dojoTabLabels.removeChild(tab.div);
delete (tab.div);
if(this.selectedTabWidget===tab){
this.selectedTabWidget=undefined;
if(this.children.length>0){
this.selectTab(this.children[0],true);
}
}
this._doSizing();
},selectTab:function(tab,_936){
if(this.selectedTabWidget){
this._hideTab(this.selectedTabWidget);
}
this.selectedTabWidget=tab;
this._showTab(tab,_936);
},tabNavigation:function(evt,tab){
if((evt.keyCode==evt.KEY_RIGHT_ARROW)||(evt.keyCode==evt.KEY_LEFT_ARROW)){
var _939=null;
var next=null;
for(var i=0;i<this.children.length;i++){
if(this.children[i]==tab){
_939=i;
break;
}
}
if(evt.keyCode==evt.KEY_RIGHT_ARROW){
next=this.children[(_939+1)%this.children.length];
}else{
next=this.children[(_939+(this.children.length-1))%this.children.length];
}
this.selectTab(next);
dojo.event.browser.stopEvent(evt);
next.div.tabTitle.focus();
}
},keyDown:function(e){
if(e.keyCode==e.KEY_UP_ARROW&&e.ctrlKey){
this.selectTab(this.selectedTabWidget);
dojo.event.browser.stopEvent(e);
this.selectedTabWidget.div.tabTitle.focus();
}
},_showTab:function(tab,_93e){
dojo.html.addClass(tab.div,"current");
tab.selected=true;
tab.div.tabTitle.setAttribute("tabIndex","0");
if(this.useVisibility&&!dojo.render.html.ie){
tab.domNode.style.visibility="visible";
}else{
if(_93e&&tab.refreshOnShow){
var tmp=tab.refreshOnShow;
tab.refreshOnShow=false;
tab.show();
tab.refreshOnShow=tmp;
}else{
tab.show();
}
if(this.doLayout){
var _940=dojo.html.getContentBox(this.containerNode);
tab.resizeTo(_940.width,_940.height);
}
}
},_hideTab:function(tab){
dojo.html.removeClass(tab.div,"current");
tab.div.tabTitle.setAttribute("tabIndex","-1");
tab.selected=false;
if(this.useVisibility){
tab.domNode.style.visibility="hidden";
}else{
tab.hide();
}
},_runOnCloseTab:function(tab){
var onc=tab.extraArgs.onClose||tab.extraArgs.onclose;
var fcn=dojo.lang.isFunction(onc)?onc:window[onc];
var _945=dojo.lang.isFunction(fcn)?fcn(this,tab):true;
if(_945){
this.removeChild(tab);
tab.destroy();
}
},onResized:function(){
this._doSizing();
}});
dojo.lang.extend(dojo.widget.Widget,{label:"",selected:false,tabCloseButton:false});
dojo.provide("dojo.widget.LinkPane");
dojo.widget.defineWidget("dojo.widget.LinkPane",dojo.widget.ContentPane,{templateString:"<div class=\"dojoLinkPane\"></div>",fillInTemplate:function(args,frag){
var _948=this.getFragNodeRef(frag);
this.label+=_948.innerHTML;
var _948=this.getFragNodeRef(frag);
dojo.html.copyStyle(this.domNode,_948);
}});
dojo.provide("dojo.widget.LayoutContainer");
dojo.widget.defineWidget("dojo.widget.LayoutContainer",dojo.widget.HtmlWidget,{isContainer:true,layoutChildPriority:"top-bottom",postCreate:function(){
dojo.widget.html.layout(this.domNode,this.children,this.layoutChildPriority);
},addChild:function(_949,_94a,pos,ref,_94d){
dojo.widget.LayoutContainer.superclass.addChild.call(this,_949,_94a,pos,ref,_94d);
dojo.widget.html.layout(this.domNode,this.children,this.layoutChildPriority);
},removeChild:function(pane){
dojo.widget.LayoutContainer.superclass.removeChild.call(this,pane);
dojo.widget.html.layout(this.domNode,this.children,this.layoutChildPriority);
},onResized:function(){
dojo.widget.html.layout(this.domNode,this.children,this.layoutChildPriority);
},show:function(){
this.domNode.style.display="";
this.checkSize();
this.domNode.style.display="none";
this.domNode.style.visibility="";
dojo.widget.LayoutContainer.superclass.show.call(this);
}});
dojo.lang.extend(dojo.widget.Widget,{layoutAlign:"none"});
dojo.provide("dojo.widget.TreeNode");
dojo.widget.tags.addParseTreeHandler("dojo:TreeNode");
dojo.widget.TreeNode=function(){
dojo.widget.HtmlWidget.call(this);
this.actionsDisabled=[];
};
dojo.inherits(dojo.widget.TreeNode,dojo.widget.HtmlWidget);
dojo.lang.extend(dojo.widget.TreeNode,{widgetType:"TreeNode",loadStates:{UNCHECKED:"UNCHECKED",LOADING:"LOADING",LOADED:"LOADED"},actions:{MOVE:"MOVE",REMOVE:"REMOVE",EDIT:"EDIT",ADDCHILD:"ADDCHILD"},isContainer:true,lockLevel:0,templateString:("<div class=\"dojoTreeNode\"> "+"<span treeNode=\"${this.widgetId}\" class=\"dojoTreeNodeLabel\" dojoAttachPoint=\"labelNode\"> "+"\t\t<span dojoAttachPoint=\"titleNode\" dojoAttachEvent=\"onClick: onTitleClick\" class=\"dojoTreeNodeLabelTitle\">${this.title}</span> "+"</span> "+"<span class=\"dojoTreeNodeAfterLabel\" dojoAttachPoint=\"afterLabelNode\">${this.afterLabel}</span> "+"<div dojoAttachPoint=\"containerNode\" style=\"display:none\"></div> "+"</div>").replace(/(>|<)\s+/g,"$1"),childIconSrc:"",childIconFolderSrc:dojo.uri.dojoUri("src/widget/templates/images/Tree/closed.gif"),childIconDocumentSrc:dojo.uri.dojoUri("src/widget/templates/images/Tree/document.gif"),childIcon:null,isTreeNode:true,objectId:"",afterLabel:"",afterLabelNode:null,expandIcon:null,title:"",object:"",isFolder:false,labelNode:null,titleNode:null,imgs:null,expandLevel:"",tree:null,depth:0,isExpanded:false,state:null,domNodeInitialized:false,isFirstNode:function(){
return this.getParentIndex()==0?true:false;
},isLastNode:function(){
return this.getParentIndex()==this.parent.children.length-1?true:false;
},lock:function(){
return this.tree.lock.apply(this,arguments);
},unlock:function(){
return this.tree.unlock.apply(this,arguments);
},isLocked:function(){
return this.tree.isLocked.apply(this,arguments);
},cleanLock:function(){
return this.tree.cleanLock.apply(this,arguments);
},actionIsDisabled:function(_94f){
var _950=this;
var _951=false;
if(this.tree.strictFolders&&_94f==this.actions.ADDCHILD&&!this.isFolder){
_951=true;
}
if(dojo.lang.inArray(_950.actionsDisabled,_94f)){
_951=true;
}
if(this.isLocked()){
_951=true;
}
return _951;
},getInfo:function(){
var info={widgetId:this.widgetId,objectId:this.objectId,index:this.getParentIndex(),isFolder:this.isFolder};
return info;
},initialize:function(args,frag){
this.state=this.loadStates.UNCHECKED;
for(var i=0;i<this.actionsDisabled.length;i++){
this.actionsDisabled[i]=this.actionsDisabled[i].toUpperCase();
}
this.expandLevel=parseInt(this.expandLevel);
},adjustDepth:function(_956){
for(var i=0;i<this.children.length;i++){
this.children[i].adjustDepth(_956);
}
this.depth+=_956;
if(_956>0){
for(var i=0;i<_956;i++){
var img=this.tree.makeBlankImg();
this.imgs.unshift(img);
dojo.html.insertBefore(this.imgs[0],this.domNode.firstChild);
}
}
if(_956<0){
for(var i=0;i<-_956;i++){
this.imgs.shift();
dojo.html.removeNode(this.domNode.firstChild);
}
}
},markLoading:function(){
this._markLoadingSavedIcon=this.expandIcon.src;
this.expandIcon.src=this.tree.expandIconSrcLoading;
},unMarkLoading:function(){
if(!this._markLoadingSavedIcon){
return;
}
var im=new Image();
im.src=this.tree.expandIconSrcLoading;
if(this.expandIcon.src==im.src){
this.expandIcon.src=this._markLoadingSavedIcon;
}
this._markLoadingSavedIcon=null;
},setFolder:function(){
dojo.event.connect(this.expandIcon,"onclick",this,"onTreeClick");
this.expandIcon.src=this.isExpanded?this.tree.expandIconSrcMinus:this.tree.expandIconSrcPlus;
this.isFolder=true;
},createDOMNode:function(tree,_95b){
this.tree=tree;
this.depth=_95b;
this.imgs=[];
for(var i=0;i<this.depth+1;i++){
var img=this.tree.makeBlankImg();
this.domNode.insertBefore(img,this.labelNode);
this.imgs.push(img);
}
this.expandIcon=this.imgs[this.imgs.length-1];
this.childIcon=this.tree.makeBlankImg();
this.imgs.push(this.childIcon);
dojo.html.insertBefore(this.childIcon,this.titleNode);
if(this.children.length||this.isFolder){
this.setFolder();
}else{
this.state=this.loadStates.LOADED;
}
dojo.event.connect(this.childIcon,"onclick",this,"onIconClick");
for(var i=0;i<this.children.length;i++){
this.children[i].parent=this;
var node=this.children[i].createDOMNode(this.tree,this.depth+1);
this.containerNode.appendChild(node);
}
if(this.children.length){
this.state=this.loadStates.LOADED;
}
this.updateIcons();
this.domNodeInitialized=true;
dojo.event.topic.publish(this.tree.eventNames.createDOMNode,{source:this});
return this.domNode;
},onTreeClick:function(e){
dojo.event.topic.publish(this.tree.eventNames.treeClick,{source:this,event:e});
},onIconClick:function(e){
dojo.event.topic.publish(this.tree.eventNames.iconClick,{source:this,event:e});
},onTitleClick:function(e){
dojo.event.topic.publish(this.tree.eventNames.titleClick,{source:this,event:e});
},markSelected:function(){
dojo.html.addClass(this.titleNode,"dojoTreeNodeLabelSelected");
},unMarkSelected:function(){
dojo.html.removeClass(this.titleNode,"dojoTreeNodeLabelSelected");
},updateExpandIcon:function(){
if(this.isFolder){
this.expandIcon.src=this.isExpanded?this.tree.expandIconSrcMinus:this.tree.expandIconSrcPlus;
}else{
this.expandIcon.src=this.tree.blankIconSrc;
}
},updateExpandGrid:function(){
if(this.tree.showGrid){
if(this.depth){
this.setGridImage(-2,this.isLastNode()?this.tree.gridIconSrcL:this.tree.gridIconSrcT);
}else{
if(this.isFirstNode()){
this.setGridImage(-2,this.isLastNode()?this.tree.gridIconSrcX:this.tree.gridIconSrcY);
}else{
this.setGridImage(-2,this.isLastNode()?this.tree.gridIconSrcL:this.tree.gridIconSrcT);
}
}
}else{
this.setGridImage(-2,this.tree.blankIconSrc);
}
},updateChildGrid:function(){
if((this.depth||this.tree.showRootGrid)&&this.tree.showGrid){
this.setGridImage(-1,(this.children.length&&this.isExpanded)?this.tree.gridIconSrcP:this.tree.gridIconSrcC);
}else{
if(this.tree.showGrid&&!this.tree.showRootGrid){
this.setGridImage(-1,(this.children.length&&this.isExpanded)?this.tree.gridIconSrcZ:this.tree.blankIconSrc);
}else{
this.setGridImage(-1,this.tree.blankIconSrc);
}
}
},updateParentGrid:function(){
var _962=this.parent;
for(var i=0;i<this.depth;i++){
var idx=this.imgs.length-(3+i);
var img=(this.tree.showGrid&&!_962.isLastNode())?this.tree.gridIconSrcV:this.tree.blankIconSrc;
this.setGridImage(idx,img);
_962=_962.parent;
}
},updateExpandGridColumn:function(){
if(!this.tree.showGrid){
return;
}
var _966=this;
var icon=this.isLastNode()?this.tree.blankIconSrc:this.tree.gridIconSrcV;
dojo.lang.forEach(_966.getDescendants(),function(node){
node.setGridImage(_966.depth,icon);
});
this.updateExpandGrid();
},updateIcons:function(){
this.imgs[0].style.display=this.tree.showRootGrid?"inline":"none";
this.buildChildIcon();
this.updateExpandGrid();
this.updateChildGrid();
this.updateParentGrid();
dojo.profile.stop("updateIcons");
},buildChildIcon:function(){
if(this.childIconSrc){
this.childIcon.src=this.childIconSrc;
}
this.childIcon.style.display=this.childIconSrc?"inline":"none";
},setGridImage:function(idx,src){
if(idx<0){
idx=this.imgs.length+idx;
}
this.imgs[idx].style.backgroundImage="url("+src+")";
},updateIconTree:function(){
this.tree.updateIconTree.call(this);
},expand:function(){
if(this.isExpanded){
return;
}
if(this.children.length){
this.showChildren();
}
this.isExpanded=true;
this.updateExpandIcon();
dojo.event.topic.publish(this.tree.eventNames.expand,{source:this});
},collapse:function(){
if(!this.isExpanded){
return;
}
this.hideChildren();
this.isExpanded=false;
this.updateExpandIcon();
dojo.event.topic.publish(this.tree.eventNames.collapse,{source:this});
},hideChildren:function(){
this.tree.toggleObj.hide(this.containerNode,this.toggleDuration,this.explodeSrc,dojo.lang.hitch(this,"onHide"));
if(dojo.exists(dojo,"dnd.dragManager.dragObjects")&&dojo.dnd.dragManager.dragObjects.length){
dojo.dnd.dragManager.cacheTargetLocations();
}
},showChildren:function(){
this.tree.toggleObj.show(this.containerNode,this.toggleDuration,this.explodeSrc,dojo.lang.hitch(this,"onShow"));
if(dojo.exists(dojo,"dnd.dragManager.dragObjects")&&dojo.dnd.dragManager.dragObjects.length){
dojo.dnd.dragManager.cacheTargetLocations();
}
},addChild:function(){
return this.tree.addChild.apply(this,arguments);
},doAddChild:function(){
return this.tree.doAddChild.apply(this,arguments);
},edit:function(_96b){
dojo.lang.mixin(this,_96b);
if(_96b.title){
this.titleNode.innerHTML=this.title;
}
if(_96b.afterLabel){
this.afterLabelNode.innerHTML=this.afterLabel;
}
if(_96b.childIconSrc){
this.buildChildIcon();
}
},removeNode:function(){
return this.tree.removeNode.apply(this,arguments);
},doRemoveNode:function(){
return this.tree.doRemoveNode.apply(this,arguments);
},toString:function(){
return "["+this.widgetType+" Tree:"+this.tree+" ID:"+this.widgetId+" Title:"+this.title+"]";
}});
dojo.provide("dojo.AdapterRegistry");
dojo.AdapterRegistry=function(_96c){
this.pairs=[];
this.returnWrappers=_96c||false;
};
dojo.lang.extend(dojo.AdapterRegistry,{register:function(name,_96e,wrap,_970,_971){
var type=(_971)?"unshift":"push";
this.pairs[type]([name,_96e,wrap,_970]);
},match:function(){
for(var i=0;i<this.pairs.length;i++){
var pair=this.pairs[i];
if(pair[1].apply(this,arguments)){
if((pair[3])||(this.returnWrappers)){
return pair[2];
}else{
return pair[2].apply(this,arguments);
}
}
}
throw new Error("No match found");
},unregister:function(name){
for(var i=0;i<this.pairs.length;i++){
var pair=this.pairs[i];
if(pair[0]==name){
this.pairs.splice(i,1);
return true;
}
}
return false;
}});
dojo.provide("dojo.json");
dojo.json={jsonRegistry:new dojo.AdapterRegistry(),register:function(name,_979,wrap,_97b){
dojo.json.jsonRegistry.register(name,_979,wrap,_97b);
},evalJson:function(json){
try{
return eval("("+json+")");
}
catch(e){
dojo.debug(e);
return json;
}
},serialize:function(o){
var _97e=typeof (o);
if(_97e=="undefined"){
return "undefined";
}else{
if((_97e=="number")||(_97e=="boolean")){
return o+"";
}else{
if(o===null){
return "null";
}
}
}
if(_97e=="string"){
return dojo.string.escapeString(o);
}
var me=arguments.callee;
var _980;
if(typeof (o.__json__)=="function"){
_980=o.__json__();
if(o!==_980){
return me(_980);
}
}
if(typeof (o.json)=="function"){
_980=o.json();
if(o!==_980){
return me(_980);
}
}
if(_97e!="function"&&typeof (o.length)=="number"){
var res=[];
for(var i=0;i<o.length;i++){
var val=me(o[i]);
if(typeof (val)!="string"){
val="undefined";
}
res.push(val);
}
return "["+res.join(",")+"]";
}
try{
window.o=o;
_980=dojo.json.jsonRegistry.match(o);
return me(_980);
}
catch(e){
}
if(_97e=="function"){
return null;
}
res=[];
for(var k in o){
var _985;
if(typeof (k)=="number"){
_985="\""+k+"\"";
}else{
if(typeof (k)=="string"){
_985=dojo.string.escapeString(k);
}else{
continue;
}
}
val=me(o[k]);
if(typeof (val)!="string"){
continue;
}
res.push(_985+":"+val);
}
return "{"+res.join(",")+"}";
}};
dojo.provide("dojo.dnd.DragSource");
dojo.provide("dojo.dnd.DropTarget");
dojo.provide("dojo.dnd.DragObject");
dojo.provide("dojo.dnd.DragAndDrop");
dojo.dnd.DragSource=function(){
var dm=dojo.dnd.dragManager;
if(dm["registerDragSource"]){
dm.registerDragSource(this);
}
};
dojo.lang.extend(dojo.dnd.DragSource,{type:"",onDragEnd:function(){
},onDragStart:function(){
},onSelected:function(){
},unregister:function(){
dojo.dnd.dragManager.unregisterDragSource(this);
},reregister:function(){
dojo.dnd.dragManager.registerDragSource(this);
}});
dojo.dnd.DragObject=function(){
var dm=dojo.dnd.dragManager;
if(dm["registerDragObject"]){
dm.registerDragObject(this);
}
};
dojo.lang.extend(dojo.dnd.DragObject,{type:"",onDragStart:function(){
},onDragMove:function(){
},onDragOver:function(){
},onDragOut:function(){
},onDragEnd:function(){
},onDragLeave:this.onDragOut,onDragEnter:this.onDragOver,ondragout:this.onDragOut,ondragover:this.onDragOver});
dojo.dnd.DropTarget=function(){
if(this.constructor==dojo.dnd.DropTarget){
return;
}
this.acceptedTypes=[];
dojo.dnd.dragManager.registerDropTarget(this);
};
dojo.lang.extend(dojo.dnd.DropTarget,{acceptsType:function(type){
if(!dojo.lang.inArray(this.acceptedTypes,"*")){
if(!dojo.lang.inArray(this.acceptedTypes,type)){
return false;
}
}
return true;
},accepts:function(_989){
if(!dojo.lang.inArray(this.acceptedTypes,"*")){
for(var i=0;i<_989.length;i++){
if(!dojo.lang.inArray(this.acceptedTypes,_989[i].type)){
return false;
}
}
}
return true;
},onDragOver:function(){
},onDragOut:function(){
},onDragMove:function(){
},onDropStart:function(){
},onDrop:function(){
},onDropEnd:function(){
}});
dojo.dnd.DragEvent=function(){
this.dragSource=null;
this.dragObject=null;
this.target=null;
this.eventStatus="success";
};
dojo.dnd.DragManager=function(){
};
dojo.lang.extend(dojo.dnd.DragManager,{selectedSources:[],dragObjects:[],dragSources:[],registerDragSource:function(){
},dropTargets:[],registerDropTarget:function(){
},lastDragTarget:null,currentDragTarget:null,onKeyDown:function(){
},onMouseOut:function(){
},onMouseMove:function(){
},onMouseUp:function(){
}});
dojo.provide("dojo.dnd.HtmlDragManager");
dojo.dnd.HtmlDragManager=function(){
};
dojo.inherits(dojo.dnd.HtmlDragManager,dojo.dnd.DragManager);
dojo.lang.extend(dojo.dnd.HtmlDragManager,{disabled:false,nestedTargets:false,mouseDownTimer:null,dsCounter:0,dsPrefix:"dojoDragSource",dropTargetDimensions:[],currentDropTarget:null,previousDropTarget:null,_dragTriggered:false,selectedSources:[],dragObjects:[],currentX:null,currentY:null,lastX:null,lastY:null,mouseDownX:null,mouseDownY:null,threshold:7,dropAcceptable:false,cancelEvent:function(e){
e.stopPropagation();
e.preventDefault();
},registerDragSource:function(ds){
if(ds["domNode"]){
var dp=this.dsPrefix;
var _98e=dp+"Idx_"+(this.dsCounter++);
ds.dragSourceId=_98e;
this.dragSources[_98e]=ds;
ds.domNode.setAttribute(dp,_98e);
if(dojo.render.html.ie){
dojo.event.browser.addListener(ds.domNode,"ondragstart",this.cancelEvent);
}
}
},unregisterDragSource:function(ds){
if(ds["domNode"]){
var dp=this.dsPrefix;
var _991=ds.dragSourceId;
delete ds.dragSourceId;
delete this.dragSources[_991];
ds.domNode.setAttribute(dp,null);
}
if(dojo.render.html.ie){
dojo.event.browser.removeListener(ds.domNode,"ondragstart",this.cancelEvent);
}
},registerDropTarget:function(dt){
this.dropTargets.push(dt);
},unregisterDropTarget:function(dt){
var _994=dojo.lang.find(this.dropTargets,dt,true);
if(_994>=0){
this.dropTargets.splice(_994,1);
}
},getDragSource:function(e){
var tn=e.target;
if(tn===dojo.body()){
return;
}
var ta=dojo.html.getAttribute(tn,this.dsPrefix);
while((!ta)&&(tn)){
tn=tn.parentNode;
if((!tn)||(tn===dojo.body())){
return;
}
ta=dojo.html.getAttribute(tn,this.dsPrefix);
}
return this.dragSources[ta];
},onKeyDown:function(e){
},onMouseDown:function(e){
if(this.disabled){
return;
}
if(dojo.render.html.ie){
if(e.button!=1){
return;
}
}else{
if(e.which!=1){
return;
}
}
var _99a=e.target.nodeType==dojo.html.TEXT_NODE?e.target.parentNode:e.target;
if(dojo.html.isTag(_99a,"button","textarea","input","select","option")){
return;
}
var ds=this.getDragSource(e);
if(!ds){
return;
}
if(!dojo.lang.inArray(this.selectedSources,ds)){
this.selectedSources.push(ds);
ds.onSelected();
}
this.mouseDownX=e.pageX;
this.mouseDownY=e.pageY;
e.preventDefault();
dojo.event.connect(document,"onmousemove",this,"onMouseMove");
},onMouseUp:function(e,_99d){
if(this.selectedSources.length==0){
return;
}
this.mouseDownX=null;
this.mouseDownY=null;
this._dragTriggered=false;
e.dragSource=this.dragSource;
if((!e.shiftKey)&&(!e.ctrlKey)){
if(this.currentDropTarget){
this.currentDropTarget.onDropStart();
}
dojo.lang.forEach(this.dragObjects,function(_99e){
var ret=null;
if(!_99e){
return;
}
if(this.currentDropTarget){
e.dragObject=_99e;
var ce=this.currentDropTarget.domNode.childNodes;
if(ce.length>0){
e.dropTarget=ce[0];
while(e.dropTarget==_99e.domNode){
e.dropTarget=e.dropTarget.nextSibling;
}
}else{
e.dropTarget=this.currentDropTarget.domNode;
}
if(this.dropAcceptable){
ret=this.currentDropTarget.onDrop(e);
}else{
this.currentDropTarget.onDragOut(e);
}
}
e.dragStatus=this.dropAcceptable&&ret?"dropSuccess":"dropFailure";
dojo.lang.delayThese([function(){
try{
_99e.dragSource.onDragEnd(e);
}
catch(err){
var _9a1={};
for(var i in e){
if(i=="type"){
_9a1.type="mouseup";
continue;
}
_9a1[i]=e[i];
}
_99e.dragSource.onDragEnd(_9a1);
}
},function(){
_99e.onDragEnd(e);
}]);
},this);
this.selectedSources=[];
this.dragObjects=[];
this.dragSource=null;
if(this.currentDropTarget){
this.currentDropTarget.onDropEnd();
}
}
dojo.event.disconnect(document,"onmousemove",this,"onMouseMove");
this.currentDropTarget=null;
},onScroll:function(){
for(var i=0;i<this.dragObjects.length;i++){
if(this.dragObjects[i].updateDragOffset){
this.dragObjects[i].updateDragOffset();
}
}
if(this.dragObjects.length){
this.cacheTargetLocations();
}
},_dragStartDistance:function(x,y){
if((!this.mouseDownX)||(!this.mouseDownX)){
return;
}
var dx=Math.abs(x-this.mouseDownX);
var dx2=dx*dx;
var dy=Math.abs(y-this.mouseDownY);
var dy2=dy*dy;
return parseInt(Math.sqrt(dx2+dy2),10);
},cacheTargetLocations:function(){
dojo.profile.start("cacheTargetLocations");
this.dropTargetDimensions=[];
dojo.lang.forEach(this.dropTargets,function(_9aa){
var tn=_9aa.domNode;
if(!tn){
return;
}
var abs=dojo.html.getAbsolutePosition(tn,true);
var bb=dojo.html.getBorderBox(tn);
this.dropTargetDimensions.push([[abs.x,abs.y],[abs.x+bb.width,abs.y+bb.height],_9aa]);
},this);
dojo.profile.end("cacheTargetLocations");
},onMouseMove:function(e){
if((dojo.render.html.ie)&&(e.button!=1)){
this.currentDropTarget=null;
this.onMouseUp(e,true);
return;
}
if((this.selectedSources.length)&&(!this.dragObjects.length)){
var dx;
var dy;
if(!this._dragTriggered){
this._dragTriggered=(this._dragStartDistance(e.pageX,e.pageY)>this.threshold);
if(!this._dragTriggered){
return;
}
dx=e.pageX-this.mouseDownX;
dy=e.pageY-this.mouseDownY;
}
this.dragSource=this.selectedSources[0];
dojo.lang.forEach(this.selectedSources,function(_9b1){
if(!_9b1){
return;
}
var tdo=_9b1.onDragStart(e);
if(tdo){
tdo.onDragStart(e);
tdo.dragOffset.y+=dy;
tdo.dragOffset.x+=dx;
tdo.dragSource=_9b1;
this.dragObjects.push(tdo);
}
},this);
this.previousDropTarget=null;
this.cacheTargetLocations();
}
dojo.lang.forEach(this.dragObjects,function(_9b3){
if(_9b3){
_9b3.onDragMove(e);
}
});
if(this.currentDropTarget){
var c=dojo.html.toCoordinateObject(this.currentDropTarget.domNode,true);
var dtp=[[c.x,c.y],[c.x+c.width,c.y+c.height]];
}
if((!this.nestedTargets)&&(dtp)&&(this.isInsideBox(e,dtp))){
if(this.dropAcceptable){
this.currentDropTarget.onDragMove(e,this.dragObjects);
}
}else{
var _9b6=this.findBestTarget(e);
if(_9b6.target===null){
if(this.currentDropTarget){
this.currentDropTarget.onDragOut(e);
this.previousDropTarget=this.currentDropTarget;
this.currentDropTarget=null;
}
this.dropAcceptable=false;
return;
}
if(this.currentDropTarget!==_9b6.target){
if(this.currentDropTarget){
this.previousDropTarget=this.currentDropTarget;
this.currentDropTarget.onDragOut(e);
}
this.currentDropTarget=_9b6.target;
e.dragObjects=this.dragObjects;
this.dropAcceptable=this.currentDropTarget.onDragOver(e);
}else{
if(this.dropAcceptable){
this.currentDropTarget.onDragMove(e,this.dragObjects);
}
}
}
},findBestTarget:function(e){
var _9b8=this;
var _9b9=new Object();
_9b9.target=null;
_9b9.points=null;
dojo.lang.every(this.dropTargetDimensions,function(_9ba){
if(!_9b8.isInsideBox(e,_9ba)){
return true;
}
_9b9.target=_9ba[2];
_9b9.points=_9ba;
return Boolean(_9b8.nestedTargets);
});
return _9b9;
},isInsideBox:function(e,_9bc){
if((e.pageX>_9bc[0][0])&&(e.pageX<_9bc[1][0])&&(e.pageY>_9bc[0][1])&&(e.pageY<_9bc[1][1])){
return true;
}
return false;
},onMouseOver:function(e){
},onMouseOut:function(e){
}});
dojo.dnd.dragManager=new dojo.dnd.HtmlDragManager();
(function(){
var d=document;
var dm=dojo.dnd.dragManager;
dojo.event.connect(d,"onkeydown",dm,"onKeyDown");
dojo.event.connect(d,"onmouseover",dm,"onMouseOver");
dojo.event.connect(d,"onmouseout",dm,"onMouseOut");
dojo.event.connect(d,"onmousedown",dm,"onMouseDown");
dojo.event.connect(d,"onmouseup",dm,"onMouseUp");
dojo.event.connect(window,"onscroll",dm,"onScroll");
})();
dojo.provide("dojo.dnd.HtmlDragAndDrop");
dojo.provide("dojo.dnd.HtmlDragSource");
dojo.provide("dojo.dnd.HtmlDropTarget");
dojo.provide("dojo.dnd.HtmlDragObject");
dojo.dnd.HtmlDragSource=function(node,type){
node=dojo.byId(node);
this.dragObjects=[];
this.constrainToContainer=false;
if(node){
this.domNode=node;
this.dragObject=node;
dojo.dnd.DragSource.call(this);
this.type=(type)||(this.domNode.nodeName.toLowerCase());
}
};
dojo.inherits(dojo.dnd.HtmlDragSource,dojo.dnd.DragSource);
dojo.lang.extend(dojo.dnd.HtmlDragSource,{dragClass:"",onDragStart:function(){
var _9c3=new dojo.dnd.HtmlDragObject(this.dragObject,this.type);
if(this.dragClass){
_9c3.dragClass=this.dragClass;
}
if(this.constrainToContainer){
_9c3.constrainTo(this.constrainingContainer||this.domNode.parentNode);
}
return _9c3;
},setDragHandle:function(node){
node=dojo.byId(node);
dojo.dnd.dragManager.unregisterDragSource(this);
this.domNode=node;
dojo.dnd.dragManager.registerDragSource(this);
},setDragTarget:function(node){
this.dragObject=node;
},constrainTo:function(_9c6){
this.constrainToContainer=true;
if(_9c6){
this.constrainingContainer=_9c6;
}
},onSelected:function(){
for(var i=0;i<this.dragObjects.length;i++){
dojo.dnd.dragManager.selectedSources.push(new dojo.dnd.HtmlDragSource(this.dragObjects[i]));
}
},addDragObjects:function(el){
for(var i=0;i<arguments.length;i++){
this.dragObjects.push(arguments[i]);
}
}});
dojo.dnd.HtmlDragObject=function(node,type){
this.domNode=dojo.byId(node);
this.type=type;
this.constrainToContainer=false;
this.dragSource=null;
};
dojo.inherits(dojo.dnd.HtmlDragObject,dojo.dnd.DragObject);
dojo.lang.extend(dojo.dnd.HtmlDragObject,{dragClass:"",opacity:0.5,createIframe:true,disableX:false,disableY:false,createDragNode:function(){
var node=this.domNode.cloneNode(true);
if(this.dragClass){
dojo.html.addClass(node,this.dragClass);
}
if(this.opacity<1){
dojo.html.setOpacity(node,this.opacity);
}
if(node.tagName.toLowerCase()=="tr"){
var doc=this.domNode.ownerDocument;
var _9ce=doc.createElement("table");
var _9cf=doc.createElement("tbody");
_9cf.appendChild(node);
_9ce.appendChild(_9cf);
var _9d0=this.domNode.childNodes;
var _9d1=node.childNodes;
for(var i=0;i<_9d0.length;i++){
if((_9d1[i])&&(_9d1[i].style)){
_9d1[i].style.width=dojo.html.getContentBox(_9d0[i]).width+"px";
}
}
node=_9ce;
}
if((dojo.render.html.ie55||dojo.render.html.ie60)&&this.createIframe){
with(node.style){
top="0px";
left="0px";
}
var _9d3=document.createElement("div");
_9d3.appendChild(node);
this.bgIframe=new dojo.html.BackgroundIframe(_9d3);
_9d3.appendChild(this.bgIframe.iframe);
node=_9d3;
}
node.style.zIndex=999;
return node;
},onDragStart:function(e){
dojo.html.clearSelection();
this.scrollOffset=dojo.html.getScroll().offset;
this.dragStartPosition=dojo.html.getAbsolutePosition(this.domNode,true);
this.dragOffset={y:this.dragStartPosition.y-e.pageY,x:this.dragStartPosition.x-e.pageX};
this.dragClone=this.createDragNode();
this.containingBlockPosition=this.domNode.offsetParent?dojo.html.getAbsolutePosition(this.domNode.offsetParent):{x:0,y:0};
if(this.constrainToContainer){
this.constraints=this.getConstraints();
}
with(this.dragClone.style){
position="absolute";
top=this.dragOffset.y+e.pageY+"px";
left=this.dragOffset.x+e.pageX+"px";
}
dojo.body().appendChild(this.dragClone);
dojo.event.connect(this.domNode,"onclick",this,"squelchOnClick");
dojo.event.topic.publish("dragStart",{source:this});
},getConstraints:function(){
if(this.constrainingContainer.nodeName.toLowerCase()=="body"){
var _9d5=dojo.html.getViewport();
var _9d6=_9d5.width;
var _9d7=_9d5.height;
var x=0;
var y=0;
}else{
var _9da=dojo.html.getContentBox(this.constrainingContainer);
_9d6=_9da.width;
_9d7=_9da.height;
x=this.containingBlockPosition.x+dojo.html.getPixelValue(this.constrainingContainer,"padding-left",true)+dojo.html.getBorderExtent(this.constrainingContainer,"left");
y=this.containingBlockPosition.y+dojo.html.getPixelValue(this.constrainingContainer,"padding-top",true)+dojo.html.getBorderExtent(this.constrainingContainer,"top");
}
var mb=dojo.html.getMarginBox(this.domNode);
return {minX:x,minY:y,maxX:x+_9d6-mb.width,maxY:y+_9d7-mb.height};
},updateDragOffset:function(){
var _9dc=dojo.html.getScroll().offset;
if(_9dc.y!=this.scrollOffset.y){
var diff=_9dc.y-this.scrollOffset.y;
this.dragOffset.y+=diff;
this.scrollOffset.y=_9dc.y;
}
if(_9dc.x!=this.scrollOffset.x){
var diff=_9dc.x-this.scrollOffset.x;
this.dragOffset.x+=diff;
this.scrollOffset.x=_9dc.x;
}
},onDragMove:function(e){
this.updateDragOffset();
var x=this.dragOffset.x+e.pageX;
var y=this.dragOffset.y+e.pageY;
if(this.constrainToContainer){
if(x<this.constraints.minX){
x=this.constraints.minX;
}
if(y<this.constraints.minY){
y=this.constraints.minY;
}
if(x>this.constraints.maxX){
x=this.constraints.maxX;
}
if(y>this.constraints.maxY){
y=this.constraints.maxY;
}
}
this.setAbsolutePosition(x,y);
dojo.event.topic.publish("dragMove",{source:this});
},setAbsolutePosition:function(x,y){
if(!this.disableY){
this.dragClone.style.top=y+"px";
}
if(!this.disableX){
this.dragClone.style.left=x+"px";
}
},onDragEnd:function(e){
switch(e.dragStatus){
case "dropSuccess":
dojo.html.removeNode(this.dragClone);
this.dragClone=null;
break;
case "dropFailure":
var _9e4=dojo.html.getAbsolutePosition(this.dragClone,true);
var _9e5={left:this.dragStartPosition.x+1,top:this.dragStartPosition.y+1};
var anim=dojo.lfx.slideTo(this.dragClone,_9e5,500,dojo.lfx.easeOut);
var _9e7=this;
dojo.event.connect(anim,"onEnd",function(e){
dojo.lang.setTimeout(function(){
dojo.html.removeNode(_9e7.dragClone);
_9e7.dragClone=null;
},200);
});
anim.play();
break;
}
dojo.event.topic.publish("dragEnd",{source:this});
},squelchOnClick:function(e){
dojo.event.browser.stopEvent(e);
dojo.lang.setTimeout(function(){
dojo.event.disconnect(this.domNode,"onclick",this,"squelchOnClick");
},50);
},constrainTo:function(_9ea){
this.constrainToContainer=true;
if(_9ea){
this.constrainingContainer=_9ea;
}else{
this.constrainingContainer=this.domNode.parentNode;
}
}});
dojo.dnd.HtmlDropTarget=function(node,_9ec){
if(arguments.length==0){
return;
}
this.domNode=dojo.byId(node);
dojo.dnd.DropTarget.call(this);
if(_9ec&&dojo.lang.isString(_9ec)){
_9ec=[_9ec];
}
this.acceptedTypes=_9ec||[];
};
dojo.inherits(dojo.dnd.HtmlDropTarget,dojo.dnd.DropTarget);
dojo.lang.extend(dojo.dnd.HtmlDropTarget,{onDragOver:function(e){
if(!this.accepts(e.dragObjects)){
return false;
}
this.childBoxes=[];
for(var i=0,child;i<this.domNode.childNodes.length;i++){
child=this.domNode.childNodes[i];
if(child.nodeType!=dojo.html.ELEMENT_NODE){
continue;
}
var pos=dojo.html.getAbsolutePosition(child,true);
var _9f0=dojo.html.getBorderBox(child);
this.childBoxes.push({top:pos.y,bottom:pos.y+_9f0.height,left:pos.x,right:pos.x+_9f0.width,node:child});
}
return true;
},_getNodeUnderMouse:function(e){
for(var i=0,child;i<this.childBoxes.length;i++){
with(this.childBoxes[i]){
if(e.pageX>=left&&e.pageX<=right&&e.pageY>=top&&e.pageY<=bottom){
return i;
}
}
}
return -1;
},createDropIndicator:function(){
this.dropIndicator=document.createElement("div");
with(this.dropIndicator.style){
position="absolute";
zIndex=999;
borderTopWidth="1px";
borderTopColor="black";
borderTopStyle="solid";
width=dojo.html.getBorderBox(this.domNode).width+"px";
left=dojo.html.getAbsolutePosition(this.domNode,true).x+"px";
}
},onDragMove:function(e,_9f4){
var i=this._getNodeUnderMouse(e);
if(!this.dropIndicator){
this.createDropIndicator();
}
if(i<0){
if(this.childBoxes.length){
var _9f6=(dojo.html.gravity(this.childBoxes[0].node,e)&dojo.html.gravity.NORTH);
}else{
var _9f6=true;
}
}else{
var _9f7=this.childBoxes[i];
var _9f6=(dojo.html.gravity(_9f7.node,e)&dojo.html.gravity.NORTH);
}
this.placeIndicator(e,_9f4,i,_9f6);
if(!dojo.html.hasParent(this.dropIndicator)){
dojo.body().appendChild(this.dropIndicator);
}
},placeIndicator:function(e,_9f9,_9fa,_9fb){
with(this.dropIndicator.style){
if(_9fa<0){
if(this.childBoxes.length){
top=(_9fb?this.childBoxes[0].top:this.childBoxes[this.childBoxes.length-1].bottom)+"px";
}else{
top=dojo.html.getAbsolutePosition(this.domNode,true).y+"px";
}
}else{
var _9fc=this.childBoxes[_9fa];
top=(_9fb?_9fc.top:_9fc.bottom)+"px";
}
}
},onDragOut:function(e){
if(this.dropIndicator){
dojo.html.removeNode(this.dropIndicator);
delete this.dropIndicator;
}
},onDrop:function(e){
this.onDragOut(e);
var i=this._getNodeUnderMouse(e);
if(i<0){
if(this.childBoxes.length){
if(dojo.html.gravity(this.childBoxes[0].node,e)&dojo.html.gravity.NORTH){
return this.insert(e,this.childBoxes[0].node,"before");
}else{
return this.insert(e,this.childBoxes[this.childBoxes.length-1].node,"after");
}
}
return this.insert(e,this.domNode,"append");
}
var _a00=this.childBoxes[i];
if(dojo.html.gravity(_a00.node,e)&dojo.html.gravity.NORTH){
return this.insert(e,_a00.node,"before");
}else{
return this.insert(e,_a00.node,"after");
}
},insert:function(e,_a02,_a03){
var node=e.dragObject.domNode;
if(_a03=="before"){
return dojo.html.insertBefore(node,_a02);
}else{
if(_a03=="after"){
return dojo.html.insertAfter(node,_a02);
}else{
if(_a03=="append"){
_a02.appendChild(node);
return true;
}
}
}
return false;
}});
dojo.provide("dojo.dnd.TreeDragAndDrop");
dojo.provide("dojo.dnd.TreeDragSource");
dojo.provide("dojo.dnd.TreeDropTarget");
dojo.provide("dojo.dnd.TreeDNDController");
dojo.dnd.TreeDragSource=function(node,_a06,type,_a08){
this.controller=_a06;
this.treeNode=_a08;
dojo.dnd.HtmlDragSource.call(this,node,type);
};
dojo.inherits(dojo.dnd.TreeDragSource,dojo.dnd.HtmlDragSource);
dojo.lang.extend(dojo.dnd.TreeDragSource,{onDragStart:function(){
var _a09=dojo.dnd.HtmlDragSource.prototype.onDragStart.call(this);
_a09.treeNode=this.treeNode;
_a09.onDragStart=dojo.lang.hitch(_a09,function(e){
this.savedSelectedNode=this.treeNode.tree.selector.selectedNode;
if(this.savedSelectedNode){
this.savedSelectedNode.unMarkSelected();
}
var _a0b=dojo.dnd.HtmlDragObject.prototype.onDragStart.apply(this,arguments);
var _a0c=this.dragClone.getElementsByTagName("img");
for(var i=0;i<_a0c.length;i++){
_a0c.item(i).style.backgroundImage="url()";
}
return _a0b;
});
_a09.onDragEnd=function(e){
if(this.savedSelectedNode){
this.savedSelectedNode.markSelected();
}
return dojo.dnd.HtmlDragObject.prototype.onDragEnd.apply(this,arguments);
};
return _a09;
},onDragEnd:function(e){
var res=dojo.dnd.HtmlDragSource.prototype.onDragEnd.call(this,e);
return res;
}});
dojo.dnd.TreeDropTarget=function(_a11,_a12,type,_a14){
this.treeNode=_a14;
this.controller=_a12;
dojo.dnd.HtmlDropTarget.apply(this,[_a11,type]);
};
dojo.inherits(dojo.dnd.TreeDropTarget,dojo.dnd.HtmlDropTarget);
dojo.lang.extend(dojo.dnd.TreeDropTarget,{autoExpandDelay:1500,autoExpandTimer:null,position:null,indicatorStyle:"2px black solid",showIndicator:function(_a15){
if(this.position==_a15){
return;
}
this.hideIndicator();
this.position=_a15;
if(_a15=="before"){
this.treeNode.labelNode.style.borderTop=this.indicatorStyle;
}else{
if(_a15=="after"){
this.treeNode.labelNode.style.borderBottom=this.indicatorStyle;
}else{
if(_a15=="onto"){
this.treeNode.markSelected();
}
}
}
},hideIndicator:function(){
this.treeNode.labelNode.style.borderBottom="";
this.treeNode.labelNode.style.borderTop="";
this.treeNode.unMarkSelected();
this.position=null;
},onDragOver:function(e){
var _a17=dojo.dnd.HtmlDropTarget.prototype.onDragOver.apply(this,arguments);
if(_a17&&this.treeNode.isFolder&&!this.treeNode.isExpanded){
this.setAutoExpandTimer();
}
return _a17;
},accepts:function(_a18){
var _a19=dojo.dnd.HtmlDropTarget.prototype.accepts.apply(this,arguments);
if(!_a19){
return false;
}
var _a1a=_a18[0].treeNode;
if(dojo.lang.isUndefined(_a1a)||!_a1a||!_a1a.isTreeNode){
dojo.raise("Source is not TreeNode or not found");
}
if(_a1a===this.treeNode){
return false;
}
return true;
},setAutoExpandTimer:function(){
var _a1b=this;
var _a1c=function(){
if(dojo.dnd.dragManager.currentDropTarget===_a1b){
_a1b.controller.expand(_a1b.treeNode);
}
};
this.autoExpandTimer=dojo.lang.setTimeout(_a1c,_a1b.autoExpandDelay);
},getDNDMode:function(){
return this.treeNode.tree.DNDMode;
},getAcceptPosition:function(e,_a1e){
var _a1f=this.getDNDMode();
if(_a1f&dojo.widget.Tree.prototype.DNDModes.ONTO&&!(!this.treeNode.actionIsDisabled(dojo.widget.TreeNode.prototype.actions.ADDCHILD)&&_a1e.parent!==this.treeNode&&this.controller.canMove(_a1e,this.treeNode))){
_a1f&=~dojo.widget.Tree.prototype.DNDModes.ONTO;
}
var _a20=this.getPosition(e,_a1f);
if(_a20=="onto"||(!this.isAdjacentNode(_a1e,_a20)&&this.controller.canMove(_a1e,this.treeNode.parent))){
return _a20;
}else{
return false;
}
},onDragOut:function(e){
this.clearAutoExpandTimer();
this.hideIndicator();
},clearAutoExpandTimer:function(){
if(this.autoExpandTimer){
clearTimeout(this.autoExpandTimer);
this.autoExpandTimer=null;
}
},onDragMove:function(e,_a23){
var _a24=_a23[0].treeNode;
var _a25=this.getAcceptPosition(e,_a24);
if(_a25){
this.showIndicator(_a25);
}
},isAdjacentNode:function(_a26,_a27){
if(_a26===this.treeNode){
return true;
}
if(_a26.getNextSibling()===this.treeNode&&_a27=="before"){
return true;
}
if(_a26.getPreviousSibling()===this.treeNode&&_a27=="after"){
return true;
}
return false;
},getPosition:function(e,_a29){
var node=dojo.byId(this.treeNode.labelNode);
var _a2b=e.pageY||e.clientY+dojo.body().scrollTop;
var _a2c=dojo.html.getAbsolutePosition(node).y;
var _a2d=dojo.html.getBorderBox(node).height;
var relY=_a2b-_a2c;
var p=relY/_a2d;
var _a30="";
if(_a29&dojo.widget.Tree.prototype.DNDModes.ONTO&&_a29&dojo.widget.Tree.prototype.DNDModes.BETWEEN){
if(p<=0.3){
_a30="before";
}else{
if(p<=0.7){
_a30="onto";
}else{
_a30="after";
}
}
}else{
if(_a29&dojo.widget.Tree.prototype.DNDModes.BETWEEN){
if(p<=0.5){
_a30="before";
}else{
_a30="after";
}
}else{
if(_a29&dojo.widget.Tree.prototype.DNDModes.ONTO){
_a30="onto";
}
}
}
return _a30;
},getTargetParentIndex:function(_a31,_a32){
var _a33=_a32=="before"?this.treeNode.getParentIndex():this.treeNode.getParentIndex()+1;
if(this.treeNode.parent===_a31.parent&&this.treeNode.getParentIndex()>_a31.getParentIndex()){
_a33--;
}
return _a33;
},onDrop:function(e){
var _a35=this.position;
this.onDragOut(e);
var _a36=e.dragObject.treeNode;
if(!dojo.lang.isObject(_a36)){
dojo.raise("TreeNode not found in dragObject");
}
if(_a35=="onto"){
return this.controller.move(_a36,this.treeNode,0);
}else{
var _a37=this.getTargetParentIndex(_a36,_a35);
return this.controller.move(_a36,this.treeNode.parent,_a37);
}
}});
dojo.dnd.TreeDNDController=function(_a38){
this.treeController=_a38;
this.dragSources={};
this.dropTargets={};
};
dojo.lang.extend(dojo.dnd.TreeDNDController,{listenTree:function(tree){
dojo.event.topic.subscribe(tree.eventNames.createDOMNode,this,"onCreateDOMNode");
dojo.event.topic.subscribe(tree.eventNames.moveFrom,this,"onMoveFrom");
dojo.event.topic.subscribe(tree.eventNames.moveTo,this,"onMoveTo");
dojo.event.topic.subscribe(tree.eventNames.addChild,this,"onAddChild");
dojo.event.topic.subscribe(tree.eventNames.removeNode,this,"onRemoveNode");
dojo.event.topic.subscribe(tree.eventNames.treeDestroy,this,"onTreeDestroy");
},unlistenTree:function(tree){
dojo.event.topic.unsubscribe(tree.eventNames.createDOMNode,this,"onCreateDOMNode");
dojo.event.topic.unsubscribe(tree.eventNames.moveFrom,this,"onMoveFrom");
dojo.event.topic.unsubscribe(tree.eventNames.moveTo,this,"onMoveTo");
dojo.event.topic.unsubscribe(tree.eventNames.addChild,this,"onAddChild");
dojo.event.topic.unsubscribe(tree.eventNames.removeNode,this,"onRemoveNode");
dojo.event.topic.unsubscribe(tree.eventNames.treeDestroy,this,"onTreeDestroy");
},onTreeDestroy:function(_a3b){
this.unlistenTree(_a3b.source);
},onCreateDOMNode:function(_a3c){
this.registerDNDNode(_a3c.source);
},onAddChild:function(_a3d){
this.registerDNDNode(_a3d.child);
},onMoveFrom:function(_a3e){
var _a3f=this;
dojo.lang.forEach(_a3e.child.getDescendants(),function(node){
_a3f.unregisterDNDNode(node);
});
},onMoveTo:function(_a41){
var _a42=this;
dojo.lang.forEach(_a41.child.getDescendants(),function(node){
_a42.registerDNDNode(node);
});
},registerDNDNode:function(node){
if(!node.tree.DNDMode){
return;
}
var _a45=null;
var _a46=null;
if(!node.actionIsDisabled(node.actions.MOVE)){
var _a45=new dojo.dnd.TreeDragSource(node.labelNode,this,node.tree.widgetId,node);
this.dragSources[node.widgetId]=_a45;
}
var _a46=new dojo.dnd.TreeDropTarget(node.labelNode,this.treeController,node.tree.DNDAcceptTypes,node);
this.dropTargets[node.widgetId]=_a46;
},unregisterDNDNode:function(node){
if(this.dragSources[node.widgetId]){
dojo.dnd.dragManager.unregisterDragSource(this.dragSources[node.widgetId]);
delete this.dragSources[node.widgetId];
}
if(this.dropTargets[node.widgetId]){
dojo.dnd.dragManager.unregisterDropTarget(this.dropTargets[node.widgetId]);
delete this.dropTargets[node.widgetId];
}
}});
dojo.provide("dojo.widget.TreeBasicController");
dojo.widget.tags.addParseTreeHandler("dojo:TreeBasicController");
dojo.widget.TreeBasicController=function(){
dojo.widget.HtmlWidget.call(this);
};
dojo.inherits(dojo.widget.TreeBasicController,dojo.widget.HtmlWidget);
dojo.lang.extend(dojo.widget.TreeBasicController,{widgetType:"TreeBasicController",DNDController:"",dieWithTree:false,initialize:function(args,frag){
if(this.DNDController=="create"){
dojo.require("dojo.dnd.TreeDragAndDrop");
this.DNDController=new dojo.dnd.TreeDNDController(this);
}
},listenTree:function(tree){
dojo.event.topic.subscribe(tree.eventNames.createDOMNode,this,"onCreateDOMNode");
dojo.event.topic.subscribe(tree.eventNames.treeClick,this,"onTreeClick");
dojo.event.topic.subscribe(tree.eventNames.treeCreate,this,"onTreeCreate");
dojo.event.topic.subscribe(tree.eventNames.treeDestroy,this,"onTreeDestroy");
if(this.DNDController){
this.DNDController.listenTree(tree);
}
},unlistenTree:function(tree){
dojo.event.topic.unsubscribe(tree.eventNames.createDOMNode,this,"onCreateDOMNode");
dojo.event.topic.unsubscribe(tree.eventNames.treeClick,this,"onTreeClick");
dojo.event.topic.unsubscribe(tree.eventNames.treeCreate,this,"onTreeCreate");
dojo.event.topic.unsubscribe(tree.eventNames.treeDestroy,this,"onTreeDestroy");
},onTreeDestroy:function(_a4c){
var tree=_a4c.source;
this.unlistenTree(tree);
if(this.dieWithTree){
this.destroy();
}
},onCreateDOMNode:function(_a4e){
var node=_a4e.source;
if(node.expandLevel>0){
this.expandToLevel(node,node.expandLevel);
}
},onTreeCreate:function(_a50){
var tree=_a50.source;
var _a52=this;
if(tree.expandLevel){
dojo.lang.forEach(tree.children,function(_a53){
_a52.expandToLevel(_a53,tree.expandLevel-1);
});
}
},expandToLevel:function(node,_a55){
if(_a55==0){
return;
}
var _a56=node.children;
var _a57=this;
var _a58=function(node,_a5a){
this.node=node;
this.expandLevel=_a5a;
this.process=function(){
for(var i=0;i<this.node.children.length;i++){
var _a5c=node.children[i];
_a57.expandToLevel(_a5c,this.expandLevel);
}
};
};
var h=new _a58(node,_a55-1);
this.expand(node,false,h,h.process);
},onTreeClick:function(_a5e){
var node=_a5e.source;
if(node.isLocked()){
return false;
}
if(node.isExpanded){
this.collapse(node);
}else{
this.expand(node);
}
},expand:function(node,sync,_a62,_a63){
node.expand();
if(_a63){
_a63.apply(_a62,[node]);
}
},collapse:function(node){
node.collapse();
},canMove:function(_a65,_a66){
if(_a65.actionIsDisabled(_a65.actions.MOVE)){
return false;
}
if(_a65.parent!==_a66&&_a66.actionIsDisabled(_a66.actions.ADDCHILD)){
return false;
}
var node=_a66;
while(node.isTreeNode){
if(node===_a65){
return false;
}
node=node.parent;
}
return true;
},move:function(_a68,_a69,_a6a){
if(!this.canMove(_a68,_a69)){
return false;
}
var _a6b=this.doMove(_a68,_a69,_a6a);
if(!_a6b){
return _a6b;
}
if(_a69.isTreeNode){
this.expand(_a69);
}
return _a6b;
},doMove:function(_a6c,_a6d,_a6e){
_a6c.tree.move(_a6c,_a6d,_a6e);
return true;
},canRemoveNode:function(_a6f){
if(_a6f.actionIsDisabled(_a6f.actions.REMOVE)){
return false;
}
return true;
},removeNode:function(node,_a71,_a72){
if(!this.canRemoveNode(node)){
return false;
}
return this.doRemoveNode(node,_a71,_a72);
},doRemoveNode:function(node,_a74,_a75){
node.tree.removeNode(node);
if(_a75){
_a75.apply(dojo.lang.isUndefined(_a74)?this:_a74,[node]);
}
},canCreateChild:function(_a76,_a77,data){
if(_a76.actionIsDisabled(_a76.actions.ADDCHILD)){
return false;
}
return true;
},createChild:function(_a79,_a7a,data,_a7c,_a7d){
if(!this.canCreateChild(_a79,_a7a,data)){
return false;
}
return this.doCreateChild.apply(this,arguments);
},doCreateChild:function(_a7e,_a7f,data,_a81,_a82){
var _a83=data.widgetType?data.widgetType:"TreeNode";
var _a84=dojo.widget.createWidget(_a83,data);
_a7e.addChild(_a84,_a7f);
this.expand(_a7e);
if(_a82){
_a82.apply(_a81,[_a84]);
}
return _a84;
}});
dojo.provide("dojo.widget.TreeSelector");
dojo.widget.tags.addParseTreeHandler("dojo:TreeSelector");
dojo.widget.TreeSelector=function(){
dojo.widget.HtmlWidget.call(this);
this.eventNames={};
this.listenedTrees=[];
};
dojo.inherits(dojo.widget.TreeSelector,dojo.widget.HtmlWidget);
dojo.lang.extend(dojo.widget.TreeSelector,{widgetType:"TreeSelector",selectedNode:null,dieWithTree:false,eventNamesDefault:{select:"select",destroy:"destroy",deselect:"deselect",dblselect:"dblselect"},initialize:function(){
for(name in this.eventNamesDefault){
if(dojo.lang.isUndefined(this.eventNames[name])){
this.eventNames[name]=this.widgetId+"/"+this.eventNamesDefault[name];
}
}
},destroy:function(){
dojo.event.topic.publish(this.eventNames.destroy,{source:this});
return dojo.widget.HtmlWidget.prototype.destroy.apply(this,arguments);
},listenTree:function(tree){
dojo.event.topic.subscribe(tree.eventNames.titleClick,this,"select");
dojo.event.topic.subscribe(tree.eventNames.iconClick,this,"select");
dojo.event.topic.subscribe(tree.eventNames.collapse,this,"onCollapse");
dojo.event.topic.subscribe(tree.eventNames.moveFrom,this,"onMoveFrom");
dojo.event.topic.subscribe(tree.eventNames.removeNode,this,"onRemoveNode");
dojo.event.topic.subscribe(tree.eventNames.treeDestroy,this,"onTreeDestroy");
this.listenedTrees.push(tree);
},unlistenTree:function(tree){
dojo.event.topic.unsubscribe(tree.eventNames.titleClick,this,"select");
dojo.event.topic.unsubscribe(tree.eventNames.iconClick,this,"select");
dojo.event.topic.unsubscribe(tree.eventNames.collapse,this,"onCollapse");
dojo.event.topic.unsubscribe(tree.eventNames.moveFrom,this,"onMoveFrom");
dojo.event.topic.unsubscribe(tree.eventNames.removeNode,this,"onRemoveNode");
dojo.event.topic.unsubscribe(tree.eventNames.treeDestroy,this,"onTreeDestroy");
for(var i=0;i<this.listenedTrees.length;i++){
if(this.listenedTrees[i]===tree){
this.listenedTrees.splice(i,1);
break;
}
}
},onTreeDestroy:function(_a88){
this.unlistenTree(_a88.source);
if(this.dieWithTree){
this.destroy();
}
},onCollapse:function(_a89){
if(!this.selectedNode){
return;
}
var node=_a89.source;
var _a8b=this.selectedNode.parent;
while(_a8b!==node&&_a8b.isTreeNode){
_a8b=_a8b.parent;
}
if(_a8b.isTreeNode){
this.deselect();
}
},select:function(_a8c){
var node=_a8c.source;
var e=_a8c.event;
if(this.selectedNode===node){
if(e.ctrlKey||e.shiftKey||e.metaKey){
this.deselect();
return;
}
dojo.event.topic.publish(this.eventNames.dblselect,{node:node});
return;
}
if(this.selectedNode){
this.deselect();
}
this.doSelect(node);
dojo.event.topic.publish(this.eventNames.select,{node:node});
},onMoveFrom:function(_a8f){
if(_a8f.child!==this.selectedNode){
return;
}
if(!dojo.lang.inArray(this.listenedTrees,_a8f.newTree)){
this.deselect();
}
},onRemoveNode:function(_a90){
if(_a90.child!==this.selectedNode){
return;
}
this.deselect();
},doSelect:function(node){
node.markSelected();
this.selectedNode=node;
},deselect:function(){
var node=this.selectedNode;
this.selectedNode=null;
node.unMarkSelected();
dojo.event.topic.publish(this.eventNames.deselect,{node:node});
}});
dojo.provide("dojo.widget.Tree");
dojo.widget.tags.addParseTreeHandler("dojo:Tree");
dojo.widget.Tree=function(){
dojo.widget.HtmlWidget.call(this);
this.eventNames={};
this.tree=this;
this.DNDAcceptTypes=[];
this.actionsDisabled=[];
};
dojo.inherits(dojo.widget.Tree,dojo.widget.HtmlWidget);
dojo.lang.extend(dojo.widget.Tree,{widgetType:"Tree",eventNamesDefault:{createDOMNode:"createDOMNode",treeCreate:"treeCreate",treeDestroy:"treeDestroy",treeClick:"treeClick",iconClick:"iconClick",titleClick:"titleClick",moveFrom:"moveFrom",moveTo:"moveTo",addChild:"addChild",removeNode:"removeNode",expand:"expand",collapse:"collapse"},isContainer:true,DNDMode:"off",lockLevel:0,strictFolders:true,DNDModes:{BETWEEN:1,ONTO:2},DNDAcceptTypes:"",templateCssString:"\n.dojoTree {\n	font: caption;\n	font-size: 11px;\n	font-weight: normal;\n	overflow: auto;\n}\n\n\n.dojoTreeNodeLabelTitle {\n	padding-left: 2px;\n	color: WindowText;\n}\n\n.dojoTreeNodeLabel {\n	cursor:hand;\n	cursor:pointer;\n}\n\n.dojoTreeNodeLabelTitle:hover {\n	text-decoration: underline;\n}\n\n.dojoTreeNodeLabelSelected {\n	background-color: Highlight;\n	color: HighlightText;\n}\n\n.dojoTree div {\n	white-space: nowrap;\n}\n\n.dojoTree img, .dojoTreeNodeLabel img {\n	vertical-align: middle;\n}\n\n",templateCssPath:dojo.uri.dojoUri("src/widget/templates/images/Tree/Tree.css"),templateString:"<div class=\"dojoTree\"></div>",isExpanded:true,isTree:true,objectId:"",controller:"",selector:"",menu:"",expandLevel:"",blankIconSrc:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_blank.gif"),gridIconSrcT:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_grid_t.gif"),gridIconSrcL:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_grid_l.gif"),gridIconSrcV:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_grid_v.gif"),gridIconSrcP:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_grid_p.gif"),gridIconSrcC:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_grid_c.gif"),gridIconSrcX:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_grid_x.gif"),gridIconSrcY:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_grid_y.gif"),gridIconSrcZ:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_grid_z.gif"),expandIconSrcPlus:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_expand_plus.gif"),expandIconSrcMinus:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_expand_minus.gif"),expandIconSrcLoading:dojo.uri.dojoUri("src/widget/templates/images/Tree/treenode_loading.gif"),iconWidth:18,iconHeight:18,showGrid:true,showRootGrid:true,actionIsDisabled:function(_a93){
var _a94=this;
return dojo.lang.inArray(_a94.actionsDisabled,_a93);
},actions:{ADDCHILD:"ADDCHILD"},getInfo:function(){
var info={widgetId:this.widgetId,objectId:this.objectId};
return info;
},initializeController:function(){
if(this.controller!="off"){
if(this.controller){
this.controller=dojo.widget.byId(this.controller);
}else{
dojo.require("dojo.widget.TreeBasicController");
this.controller=dojo.widget.createWidget("TreeBasicController",{DNDController:(this.DNDMode?"create":""),dieWithTree:true});
}
this.controller.listenTree(this);
}else{
this.controller=null;
}
},initializeSelector:function(){
if(this.selector!="off"){
if(this.selector){
this.selector=dojo.widget.byId(this.selector);
}else{
dojo.require("dojo.widget.TreeSelector");
this.selector=dojo.widget.createWidget("TreeSelector",{dieWithTree:true});
}
this.selector.listenTree(this);
}else{
this.selector=null;
}
},initialize:function(args,frag){
var _a98=this;
for(name in this.eventNamesDefault){
if(dojo.lang.isUndefined(this.eventNames[name])){
this.eventNames[name]=this.widgetId+"/"+this.eventNamesDefault[name];
}
}
for(var i=0;i<this.actionsDisabled.length;i++){
this.actionsDisabled[i]=this.actionsDisabled[i].toUpperCase();
}
if(this.DNDMode=="off"){
this.DNDMode=0;
}else{
if(this.DNDMode=="between"){
this.DNDMode=this.DNDModes.ONTO|this.DNDModes.BETWEEN;
}else{
if(this.DNDMode=="onto"){
this.DNDMode=this.DNDModes.ONTO;
}
}
}
this.expandLevel=parseInt(this.expandLevel);
this.initializeSelector();
this.initializeController();
if(this.menu){
this.menu=dojo.widget.byId(this.menu);
this.menu.listenTree(this);
}
this.containerNode=this.domNode;
},postCreate:function(){
this.createDOMNode();
},createDOMNode:function(){
dojo.html.disableSelection(this.domNode);
for(var i=0;i<this.children.length;i++){
this.children[i].parent=this;
var node=this.children[i].createDOMNode(this,0);
this.domNode.appendChild(node);
}
if(!this.showRootGrid){
for(var i=0;i<this.children.length;i++){
this.children[i].expand();
}
}
dojo.event.topic.publish(this.eventNames.treeCreate,{source:this});
},destroy:function(){
dojo.event.topic.publish(this.tree.eventNames.treeDestroy,{source:this});
return dojo.widget.HtmlWidget.prototype.destroy.apply(this,arguments);
},addChild:function(_a9c,_a9d){
var _a9e={child:_a9c,index:_a9d,parent:this,domNodeInitialized:_a9c.domNodeInitialized};
this.doAddChild.apply(this,arguments);
dojo.event.topic.publish(this.tree.eventNames.addChild,_a9e);
},doAddChild:function(_a9f,_aa0){
if(dojo.lang.isUndefined(_aa0)){
_aa0=this.children.length;
}
if(!_a9f.isTreeNode){
dojo.raise("You can only add TreeNode widgets to a "+this.widgetType+" widget!");
return;
}
if(this.isTreeNode){
if(!this.isFolder){
this.setFolder();
}
}
var _aa1=this;
dojo.lang.forEach(_a9f.getDescendants(),function(elem){
elem.tree=_aa1.tree;
});
_a9f.parent=this;
if(this.isTreeNode){
this.state=this.loadStates.LOADED;
}
if(_aa0<this.children.length){
dojo.html.insertBefore(_a9f.domNode,this.children[_aa0].domNode);
}else{
this.containerNode.appendChild(_a9f.domNode);
if(this.isExpanded&&this.isTreeNode){
this.showChildren();
}
}
this.children.splice(_aa0,0,_a9f);
if(_a9f.domNodeInitialized){
var d=this.isTreeNode?this.depth:-1;
_a9f.adjustDepth(d-_a9f.depth+1);
_a9f.updateIconTree();
}else{
_a9f.depth=this.isTreeNode?this.depth+1:0;
_a9f.createDOMNode(_a9f.tree,_a9f.depth);
}
var _aa4=_a9f.getPreviousSibling();
if(_a9f.isLastNode()&&_aa4){
_aa4.updateExpandGridColumn();
}
},makeBlankImg:function(){
var img=document.createElement("img");
img.style.width=this.iconWidth+"px";
img.style.height=this.iconHeight+"px";
img.src=this.blankIconSrc;
img.style.verticalAlign="middle";
return img;
},updateIconTree:function(){
if(!this.isTree){
this.updateIcons();
}
for(var i=0;i<this.children.length;i++){
this.children[i].updateIconTree();
}
},toString:function(){
return "["+this.widgetType+" ID:"+this.widgetId+"]";
},move:function(_aa7,_aa8,_aa9){
var _aaa=_aa7.parent;
var _aab=_aa7.tree;
this.doMove.apply(this,arguments);
var _aa8=_aa7.parent;
var _aac=_aa7.tree;
var _aad={oldParent:_aaa,oldTree:_aab,newParent:_aa8,newTree:_aac,child:_aa7};
dojo.event.topic.publish(_aab.eventNames.moveFrom,_aad);
dojo.event.topic.publish(_aac.eventNames.moveTo,_aad);
},doMove:function(_aae,_aaf,_ab0){
_aae.parent.doRemoveNode(_aae);
_aaf.doAddChild(_aae,_ab0);
},removeNode:function(_ab1){
if(!_ab1.parent){
return;
}
var _ab2=_ab1.tree;
var _ab3=_ab1.parent;
var _ab4=this.doRemoveNode.apply(this,arguments);
dojo.event.topic.publish(this.tree.eventNames.removeNode,{child:_ab4,tree:_ab2,parent:_ab3});
return _ab4;
},doRemoveNode:function(_ab5){
if(!_ab5.parent){
return;
}
var _ab6=_ab5.parent;
var _ab7=_ab6.children;
var _ab8=_ab5.getParentIndex();
if(_ab8<0){
dojo.raise("Couldn't find node "+_ab5+" for removal");
}
_ab7.splice(_ab8,1);
dojo.html.removeNode(_ab5.domNode);
if(_ab6.children.length==0){
_ab6.containerNode.style.display="none";
}
if(_ab8==_ab7.length&&_ab8>0){
_ab7[_ab8-1].updateExpandGridColumn();
}
if(_ab6 instanceof dojo.widget.Tree&&_ab8==0&&_ab7.length>0){
_ab7[0].updateExpandGrid();
}
_ab5.parent=_ab5.tree=null;
return _ab5;
},markLoading:function(){
},unMarkLoading:function(){
},lock:function(){
!this.lockLevel&&this.markLoading();
this.lockLevel++;
},unlock:function(){
if(!this.lockLevel){
dojo.raise("unlock: not locked");
}
this.lockLevel--;
!this.lockLevel&&this.unMarkLoading();
},isLocked:function(){
var node=this;
while(true){
if(node.lockLevel){
return true;
}
if(node instanceof dojo.widget.Tree){
break;
}
node=node.parent;
}
return false;
},flushLock:function(){
this.lockLevel=0;
this.unMarkLoading();
}});
dojo.provide("dojo.widget.TreeLoadingController");
dojo.widget.tags.addParseTreeHandler("dojo:TreeLoadingController");
dojo.widget.TreeLoadingController=function(){
dojo.widget.TreeBasicController.call(this);
};
dojo.inherits(dojo.widget.TreeLoadingController,dojo.widget.TreeBasicController);
dojo.lang.extend(dojo.widget.TreeLoadingController,{widgetType:"TreeLoadingController",RPCUrl:"",RPCActionParam:"action",RPCErrorHandler:function(type,obj,evt){
alert("RPC Error: "+(obj.message||"no message"));
},getRPCUrl:function(_abd){
if(this.RPCUrl=="local"){
var dir=document.location.href.substr(0,document.location.href.lastIndexOf("/"));
var _abf=dir+"/"+_abd;
return _abf;
}
if(!this.RPCUrl){
dojo.raise("Empty RPCUrl: can't load");
}
return this.RPCUrl+(this.RPCUrl.indexOf("?")>-1?"&":"?")+this.RPCActionParam+"="+_abd;
},loadProcessResponse:function(node,_ac1,_ac2,_ac3){
if(!dojo.lang.isUndefined(_ac1.error)){
this.RPCErrorHandler("server",_ac1.error);
return false;
}
var _ac4=_ac1;
if(!dojo.lang.isArray(_ac4)){
dojo.raise("loadProcessResponse: Not array loaded: "+_ac4);
}
for(var i=0;i<_ac4.length;i++){
_ac4[i]=dojo.widget.createWidget(node.widgetType,_ac4[i]);
node.addChild(_ac4[i]);
}
node.state=node.loadStates.LOADED;
if(dojo.lang.isFunction(_ac3)){
_ac3.apply(dojo.lang.isUndefined(_ac2)?this:_ac2,[node,_ac4]);
}
},getInfo:function(obj){
return obj.getInfo();
},runRPC:function(kw){
var _ac8=this;
var _ac9=function(type,data,evt){
if(kw.lock){
dojo.lang.forEach(kw.lock,function(t){
t.unlock();
});
}
if(type=="load"){
kw.load.call(this,data);
}else{
this.RPCErrorHandler(type,data,evt);
}
};
if(kw.lock){
dojo.lang.forEach(kw.lock,function(t){
t.lock();
});
}
dojo.io.bind({url:kw.url,handle:dojo.lang.hitch(this,_ac9),mimetype:"text/json",preventCache:true,sync:kw.sync,content:{data:dojo.json.serialize(kw.params)}});
},loadRemote:function(node,sync,_ad1,_ad2){
var _ad3=this;
var _ad4={node:this.getInfo(node),tree:this.getInfo(node.tree)};
this.runRPC({url:this.getRPCUrl("getChildren"),load:function(_ad5){
_ad3.loadProcessResponse(node,_ad5,_ad1,_ad2);
},sync:sync,lock:[node],params:_ad4});
},expand:function(node,sync,_ad8,_ad9){
if(node.state==node.loadStates.UNCHECKED&&node.isFolder){
this.loadRemote(node,sync,this,function(node,_adb){
this.expand(node,sync,_ad8,_ad9);
});
return;
}
dojo.widget.TreeBasicController.prototype.expand.apply(this,arguments);
},doMove:function(_adc,_add,_ade){
if(_add.isTreeNode&&_add.state==_add.loadStates.UNCHECKED){
this.loadRemote(_add,true);
}
return dojo.widget.TreeBasicController.prototype.doMove.apply(this,arguments);
},doCreateChild:function(_adf,_ae0,data,_ae2,_ae3){
if(_adf.state==_adf.loadStates.UNCHECKED){
this.loadRemote(_adf,true);
}
return dojo.widget.TreeBasicController.prototype.doCreateChild.apply(this,arguments);
}});
dojo.provide("dojo.widget.Button");
dojo.provide("dojo.widget.Button");
dojo.provide("dojo.widget.ComboButton");
dojo.provide("dojo.widget.DropDownButton");
dojo.widget.defineWidget("dojo.widget.Button",dojo.widget.HtmlWidget,{isContainer:true,caption:"",disabled:false,templateString:"<div class=\"dojoButton\" style=\"position:relative;\" dojoAttachEvent=\"onMouseOver; onMouseOut; onMouseDown; onMouseUp; onClick:buttonClick;\">\n  <div class=\"dojoButtonContents\" align=center dojoAttachPoint=\"containerNode\" style=\"position:absolute;z-index:2;\"></div>\n  <img dojoAttachPoint=\"leftImage\" style=\"position:absolute;left:0px;\">\n  <img dojoAttachPoint=\"centerImage\" style=\"position:absolute;z-index:1;\">\n  <img dojoAttachPoint=\"rightImage\" style=\"position:absolute;top:0px;right:0px;\">\n</div>\n",templateCssString:"/* ---- button --- */\n.dojoButton {\n	padding: 0 0 0 0;\n	font-size: 8pt;\n	white-space: nowrap;\n	cursor: pointer;\n	font-family: Myriad, Tahoma, Verdana, sans-serif;\n}\n\n.dojoButton .dojoButtonContents {\n	padding: 2px 2px 2px 2px;\n	text-align: center;		/* if icon and label are split across two lines, center icon */\n	color: white;\n}\n\n.dojoButtonLeftPart .dojoButtonContents {\n	padding-right: 8px;\n}\n\n.dojoButtonDisabled {\n	cursor: url(\"images/no.gif\"), default;\n}\n\n\n.dojoButtonContents img {\n	vertical-align: middle;	/* if icon and label are on same line, center them */\n}\n\n/* -------- colors ------------ */\n\n.dojoButtonHover .dojoButtonContents {\n}\n\n.dojoButtonDepressed .dojoButtonContents {\n	color: #293a4b;\n}\n\n.dojoButtonDisabled .dojoButtonContents {\n	color: #eeeeee;\n}\n\n\n/* ---------- drop down button specific ---------- */\n\n/* border between label and arrow (for drop down buttons */\n.dojoButton .border {\n	width: 1px;\n	background: gray;\n}\n\n/* button arrow */\n.dojoButton .downArrow {\n	padding-left: 10px;\n	text-align: center;\n}\n\n.dojoButton.disabled .downArrow {\n	cursor : default;\n}",templateCssPath:dojo.uri.dojoUri("src/widget/templates/HtmlButtonTemplate.css"),inactiveImg:"src/widget/templates/images/soriaButton-",activeImg:"src/widget/templates/images/soriaActive-",pressedImg:"src/widget/templates/images/soriaPressed-",disabledImg:"src/widget/templates/images/soriaDisabled-",width2height:1/3,containerNode:null,leftImage:null,centerImage:null,rightImage:null,fillInTemplate:function(args,frag){
if(this.caption!=""){
this.containerNode.appendChild(document.createTextNode(this.caption));
}
dojo.html.disableSelection(this.containerNode);
},postCreate:function(args,frag){
this.sizeMyself();
},sizeMyself:function(){
if(this.domNode.parentNode){
var _ae8=document.createElement("span");
dojo.html.insertBefore(_ae8,this.domNode);
}
dojo.body().appendChild(this.domNode);
this.sizeMyselfHelper();
if(_ae8){
dojo.html.insertBefore(this.domNode,_ae8);
dojo.html.removeNode(_ae8);
}
},sizeMyselfHelper:function(){
var mb=dojo.html.getMarginBox(this.containerNode);
this.height=mb.height;
this.containerWidth=mb.width;
var _aea=this.height*this.width2height;
this.containerNode.style.left=_aea+"px";
this.leftImage.height=this.rightImage.height=this.centerImage.height=this.height;
this.leftImage.width=this.rightImage.width=_aea+1;
this.centerImage.width=this.containerWidth;
this.centerImage.style.left=_aea+"px";
this._setImage(this.disabled?this.disabledImg:this.inactiveImg);
if(this.disabled){
dojo.html.prependClass(this.domNode,"dojoButtonDisabled");
}else{
dojo.html.removeClass(this.domNode,"dojoButtonDisabled");
}
this.domNode.style.height=this.height+"px";
this.domNode.style.width=(this.containerWidth+2*_aea)+"px";
},onMouseOver:function(e){
if(this.disabled){
return;
}
dojo.html.prependClass(this.domNode,"dojoButtonHover");
this._setImage(this.activeImg);
},onMouseDown:function(e){
if(this.disabled){
return;
}
dojo.html.prependClass(this.domNode,"dojoButtonDepressed");
dojo.html.removeClass(this.domNode,"dojoButtonHover");
this._setImage(this.pressedImg);
},onMouseUp:function(e){
if(this.disabled){
return;
}
dojo.html.prependClass(this.domNode,"dojoButtonHover");
dojo.html.removeClass(this.domNode,"dojoButtonDepressed");
this._setImage(this.activeImg);
},onMouseOut:function(e){
if(this.disabled){
return;
}
if(e.toElement&&dojo.html.isDescendantOf(e.toElement,this.domNode)){
return;
}
dojo.html.removeClass(this.domNode,"dojoButtonHover");
this._setImage(this.inactiveImg);
},buttonClick:function(e){
if(!this.disabled){
this.onClick(e);
}
},onClick:function(e){
},_setImage:function(_af1){
this.leftImage.src=dojo.uri.dojoUri(_af1+"l.gif");
this.centerImage.src=dojo.uri.dojoUri(_af1+"c.gif");
this.rightImage.src=dojo.uri.dojoUri(_af1+"r.gif");
},_toggleMenu:function(_af2){
var menu=dojo.widget.getWidgetById(_af2);
if(!menu){
return;
}
if(menu.open&&!menu.isShowingNow){
var pos=dojo.html.getAbsolutePosition(this.domNode,false);
menu.open(pos.x,pos.y+this.height,this);
}else{
if(menu.close&&menu.isShowingNow){
menu.close();
}else{
menu.toggle();
}
}
},setCaption:function(_af5){
this.caption=_af5;
this.containerNode.innerHTML=_af5;
this.sizeMyself();
},setDisabled:function(_af6){
this.disabled=_af6;
this.sizeMyself();
}});
dojo.widget.defineWidget("dojo.widget.DropDownButton",dojo.widget.Button,{menuId:"",arrow:null,downArrow:"src/widget/templates/images/whiteDownArrow.gif",disabledDownArrow:"src/widget/templates/images/whiteDownArrow.gif",fillInTemplate:function(args,frag){
dojo.widget.DropDownButton.superclass.fillInTemplate.call(this,args,frag);
this.arrow=document.createElement("img");
dojo.html.setClass(this.arrow,"downArrow");
},sizeMyselfHelper:function(){
this.arrow.src=dojo.uri.dojoUri(this.disabled?this.disabledDownArrow:this.downArrow);
this.containerNode.appendChild(this.arrow);
dojo.widget.DropDownButton.superclass.sizeMyselfHelper.call(this);
},onClick:function(e){
this._toggleMenu(this.menuId);
}});
dojo.widget.defineWidget("dojo.widget.ComboButton",dojo.widget.Button,{menuId:"",templateString:"<div class=\"dojoButton\" style=\"position:relative;top:0px;left:0px; text-align:none;\">\n\n	<div dojoAttachPoint=\"leftPart\" class=\"dojoButtonLeftPart\" style=\"position:absolute;left:0px;top:0px;\"\n		dojoAttachEvent=\"onMouseOver:leftOver; onMouseOut:leftOut; onMouseUp:leftUp; onClick:leftClick;\">\n		<div class=\"dojoButtonContents\" dojoAttachPoint=\"containerNode\" style=\"position:absolute;top:0px;right:0px;z-index:2;\"></div>\n		<img dojoAttachPoint=\"leftImage\" style=\"position:absolute;left:0px;top:0px;\">\n		<img dojoAttachPoint=\"centerImage\" style=\"position:absolute;right:0px;top:0px;z-index:1;\">\n	</div>\n\n	<div dojoAttachPoint=\"rightPart\" class=\"dojoButtonRightPart\" style=\"position:absolute;top:0px;right:0px;\"\n		dojoAttachEvent=\"onMouseOver:rightOver; onMouseOut:rightOut; onMouseUp:rightUp; onClick:rightClick;\">\n		<img dojoAttachPoint=\"arrowBackgroundImage\" style=\"position:absolute;top:0px;left:0px;z-index:1;\">\n		<img src=\"${dojoRoot}src/widget/templates/images/whiteDownArrow.gif\"\n		  		style=\"z-index:2;position:absolute;left:3px;top:50%;\">\n		<img dojoAttachPoint=\"rightImage\" style=\"position:absolute;top:0px;right:0px;\">\n	</div>\n\n</div>\n",leftPart:null,rightPart:null,arrowBackgroundImage:null,splitWidth:2,arrowWidth:5,sizeMyselfHelper:function(e){
var mb=dojo.html.getMarginBox(this.containerNode);
this.height=mb.height;
this.containerWidth=mb.width;
var _afc=this.height/3;
this.leftImage.height=this.rightImage.height=this.centerImage.height=this.arrowBackgroundImage.height=this.height;
this.leftImage.width=_afc+1;
this.centerImage.width=this.containerWidth;
this.leftPart.style.height=this.height+"px";
this.leftPart.style.width=_afc+this.containerWidth+"px";
this._setImageL(this.disabled?this.disabledImg:this.inactiveImg);
this.arrowBackgroundImage.width=this.arrowWidth;
this.rightImage.width=_afc+1;
this.rightPart.style.height=this.height+"px";
this.rightPart.style.width=this.arrowWidth+_afc+"px";
this._setImageR(this.disabled?this.disabledImg:this.inactiveImg);
this.domNode.style.height=this.height+"px";
var _afd=this.containerWidth+this.splitWidth+this.arrowWidth+2*_afc;
this.domNode.style.width=_afd+"px";
},leftOver:function(e){
if(this.disabled){
return;
}
dojo.html.prependClass(this.leftPart,"dojoButtonHover");
this._setImageL(this.activeImg);
},leftDown:function(e){
if(this.disabled){
return;
}
dojo.html.prependClass(this.leftPart,"dojoButtonDepressed");
dojo.html.removeClass(this.leftPart,"dojoButtonHover");
this._setImageL(this.pressedImg);
},leftUp:function(e){
if(this.disabled){
return;
}
dojo.html.prependClass(this.leftPart,"dojoButtonHover");
dojo.html.removeClass(this.leftPart,"dojoButtonDepressed");
this._setImageL(this.activeImg);
},leftOut:function(e){
if(this.disabled){
return;
}
dojo.html.removeClass(this.leftPart,"dojoButtonHover");
this._setImageL(this.inactiveImg);
},leftClick:function(e){
if(!this.disabled){
this.onClick(e);
}
},_setImageL:function(_b03){
this.leftImage.src=dojo.uri.dojoUri(_b03+"l.gif");
this.centerImage.src=dojo.uri.dojoUri(_b03+"c.gif");
},rightOver:function(e){
if(this.disabled){
return;
}
dojo.html.prependClass(this.rightPart,"dojoButtonHover");
this._setImageR(this.activeImg);
},rightDown:function(e){
if(this.disabled){
return;
}
dojo.html.prependClass(this.rightPart,"dojoButtonDepressed");
dojo.html.removeClass(this.rightPart,"dojoButtonHover");
this._setImageR(this.pressedImg);
},rightUp:function(e){
if(this.disabled){
return;
}
dojo.html.prependClass(this.rightPart,"dojoButtonHover");
dojo.html.removeClass(this.rightPart,"dojoButtonDepressed");
this._setImageR(this.activeImg);
},rightOut:function(e){
if(this.disabled){
return;
}
dojo.html.removeClass(this.rightPart,"dojoButtonHover");
this._setImageR(this.inactiveImg);
},rightClick:function(e){
if(this.disabled){
return;
}
this._toggleMenu(this.menuId);
},_setImageR:function(_b09){
this.arrowBackgroundImage.src=dojo.uri.dojoUri(_b09+"c.gif");
this.rightImage.src=dojo.uri.dojoUri(_b09+"r.gif");
}});
dojo.provide("dojo.widget.Dialog");
dojo.widget.defineWidget("dojo.widget.Dialog",dojo.widget.ContentPane,{templateString:"<div id=\"${this.widgetId}\" class=\"dojoDialog\" dojoAttachPoint=\"wrapper\">\n\n	<span dojoAttachPoint=\"tabStart\" \n		dojoOnFocus=\"trapTabs\" \n		dojoOnBlur=\"clearTrap\" tabindex=\"0\"></span>\n\n	<div dojoAttachPoint=\"containerNode\" style=\" position: relative; z-index: 2;\"></div>\n\n	<span dojoAttachPoint=\"tabEnd\" \n		dojoOnFocus=\"trapTabs\" \n		dojoOnBlur=\"clearTrap\" tabindex=\"0\"></span>\n\n</div>\n",isContainer:true,_scrollConnected:false,focusElement:"",bg:null,bgColor:"black",bgOpacity:0.4,followScroll:true,_fromTrap:false,anim:null,blockDuration:0,lifetime:0,trapTabs:function(e){
if(e.target==this.tabStart){
if(this._fromTrap){
this._fromTrap=false;
}else{
this._fromTrap=true;
this.tabEnd.focus();
}
}else{
if(e.target==this.tabEnd){
if(this._fromTrap){
this._fromTrap=false;
}else{
this._fromTrap=true;
this.tabStart.focus();
}
}
}
},clearTrap:function(e){
var _b0c=this;
setTimeout(function(){
_b0c._fromTrap=false;
},100);
},postCreate:function(args,frag,_b0f){
with(this.domNode.style){
position="absolute";
zIndex=999;
display="none";
overflow="visible";
}
var b=dojo.body();
b.appendChild(this.domNode);
this.bg=document.createElement("div");
this.bg.className="dialogUnderlay";
with(this.bg.style){
position="absolute";
left=top="0px";
zIndex=998;
display="none";
}
this.setBackgroundColor(this.bgColor);
b.appendChild(this.bg);
this.bgIframe=new dojo.html.BackgroundIframe(this.bg);
},setBackgroundColor:function(_b11){
if(arguments.length>=3){
_b11=new dojo.graphics.color.Color(arguments[0],arguments[1],arguments[2]);
}else{
_b11=new dojo.graphics.color.Color(_b11);
}
this.bg.style.backgroundColor=_b11.toString();
return this.bgColor=_b11;
},setBackgroundOpacity:function(op){
if(arguments.length==0){
op=this.bgOpacity;
}
dojo.html.setOpacity(this.bg,op);
try{
this.bgOpacity=dojo.html.getOpacity(this.bg);
}
catch(e){
this.bgOpacity=op;
}
return this.bgOpacity;
},sizeBackground:function(){
if(this.bgOpacity>0){
var _b13=dojo.html.getViewport();
var h=Math.max(dojo.doc().documentElement.scrollHeight||dojo.body().scrollHeight,_b13.height);
var w=_b13.width;
this.bg.style.width=w+"px";
this.bg.style.height=h+"px";
}
this.bgIframe.onResized();
},showBackground:function(){
this.sizeBackground();
if(this.bgOpacity>0){
this.bg.style.display="block";
}
},placeDialog:function(){
var _b16=dojo.html.getScroll().offset;
var _b17=dojo.html.getViewport();
var mb=dojo.html.getMarginBox(this.containerNode);
var x=_b16.x+(_b17.width-mb.width)/2;
var y=_b16.y+(_b17.height-mb.height)/2;
with(this.domNode.style){
left=x+"px";
top=y+"px";
}
},show:function(){
this.setBackgroundOpacity();
this.showBackground();
dojo.widget.Dialog.superclass.show.call(this);
if(this.followScroll&&!this._scrollConnected){
this._scrollConnected=true;
dojo.event.connect(window,"onscroll",this,"onScroll");
}
if(this.lifetime){
this.timeRemaining=this.lifetime;
if(!this.blockDuration){
dojo.event.connect(this.bg,"onclick",this,"hide");
}else{
dojo.event.disconnect(this.bg,"onclick",this,"hide");
}
if(this.timerNode){
this.timerNode.innerHTML=Math.ceil(this.timeRemaining/1000);
}
if(this.blockDuration&&this.closeNode){
if(this.lifetime>this.blockDuration){
this.closeNode.style.visibility="hidden";
}else{
this.closeNode.style.display="none";
}
}
this.timer=setInterval(dojo.lang.hitch(this,"onTick"),100);
}
this.checkSize();
},onLoad:function(){
this.placeDialog();
},fillInTemplate:function(){
},hide:function(){
if(this.focusElement){
dojo.byId(this.focusElement).focus();
dojo.byId(this.focusElement).blur();
}
if(this.timer){
clearInterval(this.timer);
}
this.bg.style.display="none";
this.bg.style.width=this.bg.style.height="1px";
dojo.widget.Dialog.superclass.hide.call(this);
if(this._scrollConnected){
this._scrollConnected=false;
dojo.event.disconnect(window,"onscroll",this,"onScroll");
}
},setTimerNode:function(node){
this.timerNode=node;
},setCloseControl:function(node){
this.closeNode=node;
dojo.event.connect(node,"onclick",this,"hide");
},setShowControl:function(node){
dojo.event.connect(node,"onclick",this,"show");
},onTick:function(){
if(this.timer){
this.timeRemaining-=100;
if(this.lifetime-this.timeRemaining>=this.blockDuration){
dojo.event.connect(this.bg,"onclick",this,"hide");
if(this.closeNode){
this.closeNode.style.visibility="visible";
}
}
if(!this.timeRemaining){
clearInterval(this.timer);
this.hide();
}else{
if(this.timerNode){
this.timerNode.innerHTML=Math.ceil(this.timeRemaining/1000);
}
}
}
},onScroll:function(){
this.placeDialog();
this.domNode.style.display="block";
},checkSize:function(){
if(this.isShowing()){
this.sizeBackground();
this.placeDialog();
this.domNode.style.display="block";
this.onResized();
}
},killEvent:function(evt){
evt.preventDefault();
evt.stopPropagation();
}});
dojo.provide("dojo.widget.ToolbarContainer");
dojo.provide("dojo.widget.Toolbar");
dojo.provide("dojo.widget.ToolbarItem");
dojo.provide("dojo.widget.ToolbarButtonGroup");
dojo.provide("dojo.widget.ToolbarButton");
dojo.provide("dojo.widget.ToolbarDialog");
dojo.provide("dojo.widget.ToolbarMenu");
dojo.provide("dojo.widget.ToolbarSeparator");
dojo.provide("dojo.widget.ToolbarSpace");
dojo.provide("dojo.widget.Icon");
dojo.widget.defineWidget("dojo.widget.ToolbarContainer",dojo.widget.HtmlWidget,{isContainer:true,templateString:"<div class=\"toolbarContainer\" dojoAttachPoint=\"containerNode\"></div>",templateCssString:".toolbarContainer {\n	border-bottom : 0;\n	background-color : #def;\n	color : ButtonText;\n	font : Menu;\n	background-image: url(images/toolbar-bg.gif);\n}\n\n.toolbar {\n	padding : 2px 4px;\n	min-height : 26px;\n	_height : 26px;\n}\n\n.toolbarItem {\n	float : left;\n	padding : 1px 2px;\n	margin : 0 2px 1px 0;\n	cursor : pointer;\n}\n\n.toolbarItem.selected, .toolbarItem.down {\n	margin : 1px 1px 0 1px;\n	padding : 0px 1px;\n	border : 1px solid #bbf;\n	background-color : #fafaff;\n}\n\n.toolbarButton img {\n	vertical-align : bottom;\n}\n\n.toolbarButton span {\n	line-height : 16px;\n	vertical-align : middle;\n}\n\n.toolbarButton.hover {\n	padding : 0px 1px;\n	border : 1px solid #99c;\n}\n\n.toolbarItem.disabled {\n	opacity : 0.3;\n	filter : alpha(opacity=30);\n	cursor : default;\n}\n\n.toolbarSeparator {\n	cursor : default;\n}\n\n.toolbarFlexibleSpace {\n}\n",templateCssPath:dojo.uri.dojoUri("src/widget/templates/HtmlToolbar.css"),getItem:function(name){
if(name instanceof dojo.widget.ToolbarItem){
return name;
}
for(var i=0;i<this.children.length;i++){
var _b21=this.children[i];
if(_b21 instanceof dojo.widget.Toolbar){
var item=_b21.getItem(name);
if(item){
return item;
}
}
}
return null;
},getItems:function(){
var _b23=[];
for(var i=0;i<this.children.length;i++){
var _b25=this.children[i];
if(_b25 instanceof dojo.widget.Toolbar){
_b23=_b23.concat(_b25.getItems());
}
}
return _b23;
},enable:function(){
for(var i=0;i<this.children.length;i++){
var _b27=this.children[i];
if(_b27 instanceof dojo.widget.Toolbar){
_b27.enable.apply(_b27,arguments);
}
}
},disable:function(){
for(var i=0;i<this.children.length;i++){
var _b29=this.children[i];
if(_b29 instanceof dojo.widget.Toolbar){
_b29.disable.apply(_b29,arguments);
}
}
},select:function(name){
for(var i=0;i<this.children.length;i++){
var _b2c=this.children[i];
if(_b2c instanceof dojo.widget.Toolbar){
_b2c.select(arguments);
}
}
},deselect:function(name){
for(var i=0;i<this.children.length;i++){
var _b2f=this.children[i];
if(_b2f instanceof dojo.widget.Toolbar){
_b2f.deselect(arguments);
}
}
},getItemsState:function(){
var _b30={};
for(var i=0;i<this.children.length;i++){
var _b32=this.children[i];
if(_b32 instanceof dojo.widget.Toolbar){
dojo.lang.mixin(_b30,_b32.getItemsState());
}
}
return _b30;
},getItemsActiveState:function(){
var _b33={};
for(var i=0;i<this.children.length;i++){
var _b35=this.children[i];
if(_b35 instanceof dojo.widget.Toolbar){
dojo.lang.mixin(_b33,_b35.getItemsActiveState());
}
}
return _b33;
},getItemsSelectedState:function(){
var _b36={};
for(var i=0;i<this.children.length;i++){
var _b38=this.children[i];
if(_b38 instanceof dojo.widget.Toolbar){
dojo.lang.mixin(_b36,_b38.getItemsSelectedState());
}
}
return _b36;
}});
dojo.widget.defineWidget("dojo.widget.Toolbar",dojo.widget.HtmlWidget,{isContainer:true,templateString:"<div class=\"toolbar\" dojoAttachPoint=\"containerNode\" unselectable=\"on\" dojoOnMouseover=\"_onmouseover\" dojoOnMouseout=\"_onmouseout\" dojoOnClick=\"_onclick\" dojoOnMousedown=\"_onmousedown\" dojoOnMouseup=\"_onmouseup\"></div>",_getItem:function(node){
var _b3a=new Date();
var _b3b=null;
while(node&&node!=this.domNode){
if(dojo.html.hasClass(node,"toolbarItem")){
var _b3c=dojo.widget.manager.getWidgetsByFilter(function(w){
return w.domNode==node;
});
if(_b3c.length==1){
_b3b=_b3c[0];
break;
}else{
if(_b3c.length>1){
dojo.raise("Toolbar._getItem: More than one widget matches the node");
}
}
}
node=node.parentNode;
}
return _b3b;
},_onmouseover:function(e){
var _b3f=this._getItem(e.target);
if(_b3f&&_b3f._onmouseover){
_b3f._onmouseover(e);
}
},_onmouseout:function(e){
var _b41=this._getItem(e.target);
if(_b41&&_b41._onmouseout){
_b41._onmouseout(e);
}
},_onclick:function(e){
var _b43=this._getItem(e.target);
if(_b43&&_b43._onclick){
_b43._onclick(e);
}
},_onmousedown:function(e){
var _b45=this._getItem(e.target);
if(_b45&&_b45._onmousedown){
_b45._onmousedown(e);
}
},_onmouseup:function(e){
var _b47=this._getItem(e.target);
if(_b47&&_b47._onmouseup){
_b47._onmouseup(e);
}
},addChild:function(item,pos,_b4a){
var _b4b=dojo.widget.ToolbarItem.make(item,null,_b4a);
var ret=dojo.widget.Toolbar.superclass.addChild.call(this,_b4b,null,pos,null);
return ret;
},push:function(){
for(var i=0;i<arguments.length;i++){
this.addChild(arguments[i]);
}
},getItem:function(name){
if(name instanceof dojo.widget.ToolbarItem){
return name;
}
for(var i=0;i<this.children.length;i++){
var _b50=this.children[i];
if(_b50 instanceof dojo.widget.ToolbarItem&&_b50._name==name){
return _b50;
}
}
return null;
},getItems:function(){
var _b51=[];
for(var i=0;i<this.children.length;i++){
var _b53=this.children[i];
if(_b53 instanceof dojo.widget.ToolbarItem){
_b51.push(_b53);
}
}
return _b51;
},getItemsState:function(){
var _b54={};
for(var i=0;i<this.children.length;i++){
var _b56=this.children[i];
if(_b56 instanceof dojo.widget.ToolbarItem){
_b54[_b56._name]={selected:_b56._selected,enabled:_b56._enabled};
}
}
return _b54;
},getItemsActiveState:function(){
var _b57=this.getItemsState();
for(var item in _b57){
_b57[item]=_b57[item].enabled;
}
return _b57;
},getItemsSelectedState:function(){
var _b59=this.getItemsState();
for(var item in _b59){
_b59[item]=_b59[item].selected;
}
return _b59;
},enable:function(){
var _b5b=arguments.length?arguments:this.children;
for(var i=0;i<_b5b.length;i++){
var _b5d=this.getItem(_b5b[i]);
if(_b5d instanceof dojo.widget.ToolbarItem){
_b5d.enable(false,true);
}
}
},disable:function(){
var _b5e=arguments.length?arguments:this.children;
for(var i=0;i<_b5e.length;i++){
var _b60=this.getItem(_b5e[i]);
if(_b60 instanceof dojo.widget.ToolbarItem){
_b60.disable();
}
}
},select:function(){
for(var i=0;i<arguments.length;i++){
var name=arguments[i];
var item=this.getItem(name);
if(item){
item.select();
}
}
},deselect:function(){
for(var i=0;i<arguments.length;i++){
var name=arguments[i];
var item=this.getItem(name);
if(item){
item.disable();
}
}
},setValue:function(){
for(var i=0;i<arguments.length;i+=2){
var name=arguments[i],value=arguments[i+1];
var item=this.getItem(name);
if(item){
if(item instanceof dojo.widget.ToolbarItem){
item.setValue(value);
}
}
}
}});
dojo.widget.defineWidget("dojo.widget.ToolbarItem",dojo.widget.HtmlWidget,{templateString:"<span unselectable=\"on\" class=\"toolbarItem\"></span>",_name:null,getName:function(){
return this._name;
},setName:function(_b6a){
return (this._name=_b6a);
},getValue:function(){
return this.getName();
},setValue:function(_b6b){
return this.setName(_b6b);
},_selected:false,isSelected:function(){
return this._selected;
},setSelected:function(is,_b6d,_b6e){
if(!this._toggleItem&&!_b6d){
return;
}
is=Boolean(is);
if(_b6d||this._enabled&&this._selected!=is){
this._selected=is;
this.update();
if(!_b6e){
this._fireEvent(is?"onSelect":"onDeselect");
this._fireEvent("onChangeSelect");
}
}
},select:function(_b6f,_b70){
return this.setSelected(true,_b6f,_b70);
},deselect:function(_b71,_b72){
return this.setSelected(false,_b71,_b72);
},_toggleItem:false,isToggleItem:function(){
return this._toggleItem;
},setToggleItem:function(_b73){
this._toggleItem=Boolean(_b73);
},toggleSelected:function(_b74){
return this.setSelected(!this._selected,_b74);
},_enabled:true,isEnabled:function(){
return this._enabled;
},setEnabled:function(is,_b76,_b77){
is=Boolean(is);
if(_b76||this._enabled!=is){
this._enabled=is;
this.update();
if(!_b77){
this._fireEvent(this._enabled?"onEnable":"onDisable");
this._fireEvent("onChangeEnabled");
}
}
return this._enabled;
},enable:function(_b78,_b79){
return this.setEnabled(true,_b78,_b79);
},disable:function(_b7a,_b7b){
return this.setEnabled(false,_b7a,_b7b);
},toggleEnabled:function(_b7c,_b7d){
return this.setEnabled(!this._enabled,_b7c,_b7d);
},_icon:null,getIcon:function(){
return this._icon;
},setIcon:function(_b7e){
var icon=dojo.widget.Icon.make(_b7e);
if(this._icon){
this._icon.setIcon(icon);
}else{
this._icon=icon;
}
var _b80=this._icon.getNode();
if(_b80.parentNode!=this.domNode){
if(this.domNode.hasChildNodes()){
this.domNode.insertBefore(_b80,this.domNode.firstChild);
}else{
this.domNode.appendChild(_b80);
}
}
return this._icon;
},_label:"",getLabel:function(){
return this._label;
},setLabel:function(_b81){
var ret=(this._label=_b81);
if(!this.labelNode){
this.labelNode=document.createElement("span");
this.domNode.appendChild(this.labelNode);
}
this.labelNode.innerHTML="";
this.labelNode.appendChild(document.createTextNode(this._label));
this.update();
return ret;
},update:function(){
if(this._enabled){
dojo.html.removeClass(this.domNode,"disabled");
if(this._selected){
dojo.html.addClass(this.domNode,"selected");
}else{
dojo.html.removeClass(this.domNode,"selected");
}
}else{
this._selected=false;
dojo.html.addClass(this.domNode,"disabled");
dojo.html.removeClass(this.domNode,"down");
dojo.html.removeClass(this.domNode,"hover");
}
this._updateIcon();
},_updateIcon:function(){
if(this._icon){
if(this._enabled){
if(this._cssHover){
this._icon.hover();
}else{
if(this._selected){
this._icon.select();
}else{
this._icon.enable();
}
}
}else{
this._icon.disable();
}
}
},_fireEvent:function(evt){
if(typeof this[evt]=="function"){
var args=[this];
for(var i=1;i<arguments.length;i++){
args.push(arguments[i]);
}
this[evt].apply(this,args);
}
},_onmouseover:function(e){
if(!this._enabled){
return;
}
dojo.html.addClass(this.domNode,"hover");
},_onmouseout:function(e){
dojo.html.removeClass(this.domNode,"hover");
dojo.html.removeClass(this.domNode,"down");
if(!this._selected){
dojo.html.removeClass(this.domNode,"selected");
}
},_onclick:function(e){
if(this._enabled&&!this._toggleItem){
this._fireEvent("onClick");
}
},_onmousedown:function(e){
if(e.preventDefault){
e.preventDefault();
}
if(!this._enabled){
return;
}
dojo.html.addClass(this.domNode,"down");
if(this._toggleItem){
if(this.parent.preventDeselect&&this._selected){
return;
}
this.toggleSelected();
}
},_onmouseup:function(e){
dojo.html.removeClass(this.domNode,"down");
},fillInTemplate:function(args,frag){
if(args.name){
this._name=args.name;
}
if(args.selected){
this.select();
}
if(args.disabled){
this.disable();
}
if(args.label){
this.setLabel(args.label);
}
if(args.icon){
this.setIcon(args.icon);
}
if(args.toggleitem||args.toggleItem){
this.setToggleItem(true);
}
}});
dojo.widget.ToolbarItem.make=function(wh,_b8e,_b8f){
var item=null;
if(wh instanceof Array){
item=dojo.widget.createWidget("ToolbarButtonGroup",_b8f);
item.setName(wh[0]);
for(var i=1;i<wh.length;i++){
item.addChild(wh[i]);
}
}else{
if(wh instanceof dojo.widget.ToolbarItem){
item=wh;
}else{
if(wh instanceof dojo.uri.Uri){
item=dojo.widget.createWidget("ToolbarButton",dojo.lang.mixin(_b8f||{},{icon:new dojo.widget.Icon(wh.toString())}));
}else{
if(_b8e){
item=dojo.widget.createWidget(wh,_b8f);
}else{
if(typeof wh=="string"||wh instanceof String){
switch(wh.charAt(0)){
case "|":
case "-":
case "/":
item=dojo.widget.createWidget("ToolbarSeparator",_b8f);
break;
case " ":
if(wh.length==1){
item=dojo.widget.createWidget("ToolbarSpace",_b8f);
}else{
item=dojo.widget.createWidget("ToolbarFlexibleSpace",_b8f);
}
break;
default:
if(/\.(gif|jpg|jpeg|png)$/i.test(wh)){
item=dojo.widget.createWidget("ToolbarButton",dojo.lang.mixin(_b8f||{},{icon:new dojo.widget.Icon(wh.toString())}));
}else{
item=dojo.widget.createWidget("ToolbarButton",dojo.lang.mixin(_b8f||{},{label:wh.toString()}));
}
}
}else{
if(wh&&wh.tagName&&/^img$/i.test(wh.tagName)){
item=dojo.widget.createWidget("ToolbarButton",dojo.lang.mixin(_b8f||{},{icon:wh}));
}else{
item=dojo.widget.createWidget("ToolbarButton",dojo.lang.mixin(_b8f||{},{label:wh.toString()}));
}
}
}
}
}
}
return item;
};
dojo.widget.defineWidget("dojo.widget.ToolbarButtonGroup",dojo.widget.ToolbarItem,{isContainer:true,templateString:"<span unselectable=\"on\" class=\"toolbarButtonGroup\" dojoAttachPoint=\"containerNode\"></span>",defaultButton:"",postCreate:function(){
for(var i=0;i<this.children.length;i++){
this._injectChild(this.children[i]);
}
},addChild:function(item,pos,_b95){
var _b96=dojo.widget.ToolbarItem.make(item,null,dojo.lang.mixin(_b95||{},{toggleItem:true}));
var ret=dojo.widget.ToolbarButtonGroup.superclass.addChild.call(this,_b96,null,pos,null);
this._injectChild(_b96);
return ret;
},_injectChild:function(_b98){
dojo.event.connect(_b98,"onSelect",this,"onChildSelected");
dojo.event.connect(_b98,"onDeselect",this,"onChildDeSelected");
if(_b98._name==this.defaultButton||(typeof this.defaultButton=="number"&&this.children.length-1==this.defaultButton)){
_b98.select(false,true);
}
},getItem:function(name){
if(name instanceof dojo.widget.ToolbarItem){
return name;
}
for(var i=0;i<this.children.length;i++){
var _b9b=this.children[i];
if(_b9b instanceof dojo.widget.ToolbarItem&&_b9b._name==name){
return _b9b;
}
}
return null;
},getItems:function(){
var _b9c=[];
for(var i=0;i<this.children.length;i++){
var _b9e=this.children[i];
if(_b9e instanceof dojo.widget.ToolbarItem){
_b9c.push(_b9e);
}
}
return _b9c;
},onChildSelected:function(e){
this.select(e._name);
},onChildDeSelected:function(e){
this._fireEvent("onChangeSelect",this._value);
},enable:function(_ba1,_ba2){
for(var i=0;i<this.children.length;i++){
var _ba4=this.children[i];
if(_ba4 instanceof dojo.widget.ToolbarItem){
_ba4.enable(_ba1,_ba2);
if(_ba4._name==this._value){
_ba4.select(_ba1,_ba2);
}
}
}
},disable:function(_ba5,_ba6){
for(var i=0;i<this.children.length;i++){
var _ba8=this.children[i];
if(_ba8 instanceof dojo.widget.ToolbarItem){
_ba8.disable(_ba5,_ba6);
}
}
},_value:"",getValue:function(){
return this._value;
},select:function(name,_baa,_bab){
for(var i=0;i<this.children.length;i++){
var _bad=this.children[i];
if(_bad instanceof dojo.widget.ToolbarItem){
if(_bad._name==name){
_bad.select(_baa,_bab);
this._value=name;
}else{
_bad.deselect(true,true);
}
}
}
if(!_bab){
this._fireEvent("onSelect",this._value);
this._fireEvent("onChangeSelect",this._value);
}
},setValue:this.select,preventDeselect:false});
dojo.widget.defineWidget("dojo.widget.ToolbarButton",dojo.widget.ToolbarItem,{fillInTemplate:function(args,frag){
dojo.widget.ToolbarButton.superclass.fillInTemplate.call(this,args,frag);
dojo.html.addClass(this.domNode,"toolbarButton");
if(this._icon){
this.setIcon(this._icon);
}
if(this._label){
this.setLabel(this._label);
}
if(!this._name){
if(this._label){
this.setName(this._label);
}else{
if(this._icon){
var src=this._icon.getSrc("enabled").match(/[\/^]([^\.\/]+)\.(gif|jpg|jpeg|png)$/i);
if(src){
this.setName(src[1]);
}
}else{
this._name=this._widgetId;
}
}
}
}});
dojo.widget.defineWidget("dojo.widget.ToolbarDialog",dojo.widget.ToolbarButton,{fillInTemplate:function(args,frag){
dojo.widget.ToolbarDialog.superclass.fillInTemplate.call(this,args,frag);
dojo.event.connect(this,"onSelect",this,"showDialog");
dojo.event.connect(this,"onDeselect",this,"hideDialog");
},showDialog:function(e){
dojo.lang.setTimeout(dojo.event.connect,1,document,"onmousedown",this,"deselect");
},hideDialog:function(e){
dojo.event.disconnect(document,"onmousedown",this,"deselect");
}});
dojo.widget.defineWidget("dojo.widget.ToolbarMenu",dojo.widget.ToolbarDialog,{});
dojo.widget.ToolbarMenuItem=function(){
};
dojo.widget.defineWidget("dojo.widget.ToolbarSeparator",dojo.widget.ToolbarItem,{templateString:"<span unselectable=\"on\" class=\"toolbarItem toolbarSeparator\"></span>",defaultIconPath:new dojo.uri.dojoUri("src/widget/templates/buttons/sep.gif"),fillInTemplate:function(args,frag,skip){
dojo.widget.ToolbarSeparator.superclass.fillInTemplate.call(this,args,frag);
this._name=this.widgetId;
if(!skip){
if(!this._icon){
this.setIcon(this.defaultIconPath);
}
this.domNode.appendChild(this._icon.getNode());
}
},_onmouseover:null,_onmouseout:null,_onclick:null,_onmousedown:null,_onmouseup:null});
dojo.widget.defineWidget("dojo.widget.ToolbarSpace",dojo.widget.ToolbarSeparator,{fillInTemplate:function(args,frag,skip){
dojo.widget.ToolbarSpace.superclass.fillInTemplate.call(this,args,frag,true);
if(!skip){
dojo.html.addClass(this.domNode,"toolbarSpace");
}
}});
dojo.widget.defineWidget("dojo.widget.ToolbarSelect",dojo.widget.ToolbarItem,{templateString:"<span class=\"toolbarItem toolbarSelect\" unselectable=\"on\"><select dojoAttachPoint=\"selectBox\" dojoOnChange=\"changed\"></select></span>",fillInTemplate:function(args,frag){
dojo.widget.ToolbarSelect.superclass.fillInTemplate.call(this,args,frag,true);
var keys=args.values;
var i=0;
for(var val in keys){
var opt=document.createElement("option");
opt.setAttribute("value",keys[val]);
opt.innerHTML=val;
this.selectBox.appendChild(opt);
}
},changed:function(e){
this._fireEvent("onSetValue",this.selectBox.value);
},setEnabled:function(is,_bc3,_bc4){
var ret=dojo.widget.ToolbarSelect.superclass.setEnabled.call(this,is,_bc3,_bc4);
this.selectBox.disabled=!this._enabled;
return ret;
},_onmouseover:null,_onmouseout:null,_onclick:null,_onmousedown:null,_onmouseup:null});
dojo.widget.Icon=function(_bc6,_bc7,_bc8,_bc9){
if(!arguments.length){
throw new Error("Icon must have at least an enabled state");
}
var _bca=["enabled","disabled","hover","selected"];
var _bcb="enabled";
var _bcc=document.createElement("img");
this.getState=function(){
return _bcb;
};
this.setState=function(_bcd){
if(dojo.lang.inArray(_bcd,_bca)){
if(this[_bcd]){
_bcb=_bcd;
_bcc.setAttribute("src",this[_bcb].src);
}
}else{
throw new Error("Invalid state set on Icon (state: "+_bcd+")");
}
};
this.setSrc=function(_bce,_bcf){
if(/^img$/i.test(_bcf.tagName)){
this[_bce]=_bcf;
}else{
if(typeof _bcf=="string"||_bcf instanceof String||_bcf instanceof dojo.uri.Uri){
this[_bce]=new Image();
this[_bce].src=_bcf.toString();
}
}
return this[_bce];
};
this.setIcon=function(icon){
for(var i=0;i<_bca.length;i++){
if(icon[_bca[i]]){
this.setSrc(_bca[i],icon[_bca[i]]);
}
}
this.update();
};
this.enable=function(){
this.setState("enabled");
};
this.disable=function(){
this.setState("disabled");
};
this.hover=function(){
this.setState("hover");
};
this.select=function(){
this.setState("selected");
};
this.getSize=function(){
return {width:_bcc.width||_bcc.offsetWidth,height:_bcc.height||_bcc.offsetHeight};
};
this.setSize=function(w,h){
_bcc.width=w;
_bcc.height=h;
return {width:w,height:h};
};
this.getNode=function(){
return _bcc;
};
this.getSrc=function(_bd4){
if(_bd4){
return this[_bd4].src;
}
return _bcc.src||"";
};
this.update=function(){
this.setState(_bcb);
};
for(var i=0;i<_bca.length;i++){
var arg=arguments[i];
var _bd7=_bca[i];
this[_bd7]=null;
if(!arg){
continue;
}
this.setSrc(_bd7,arg);
}
this.enable();
};
dojo.widget.Icon.make=function(a,b,c,d){
for(var i=0;i<arguments.length;i++){
if(arguments[i] instanceof dojo.widget.Icon){
return arguments[i];
}
}
return new dojo.widget.Icon(a,b,c,d);
};
dojo.provide("dojo.collections.Collections");
dojo.collections={Collections:true};
dojo.collections.DictionaryEntry=function(k,v){
this.key=k;
this.value=v;
this.valueOf=function(){
return this.value;
};
this.toString=function(){
return String(this.value);
};
};
dojo.collections.Iterator=function(arr){
var a=arr;
var _be1=0;
this.element=a[_be1]||null;
this.atEnd=function(){
return (_be1>=a.length);
};
this.get=function(){
if(this.atEnd()){
return null;
}
this.element=a[_be1++];
return this.element;
};
this.map=function(fn,_be3){
var s=_be3||dj_global;
if(Array.map){
return Array.map(a,fn,s);
}else{
var arr=[];
for(var i=0;i<a.length;i++){
arr.push(fn.call(s,a[i]));
}
return arr;
}
};
this.reset=function(){
_be1=0;
this.element=a[_be1];
};
};
dojo.collections.DictionaryIterator=function(obj){
var a=[];
var _be9={};
for(var p in obj){
if(!_be9[p]){
a.push(obj[p]);
}
}
var _beb=0;
this.element=a[_beb]||null;
this.atEnd=function(){
return (_beb>=a.length);
};
this.get=function(){
if(this.atEnd()){
return null;
}
this.element=a[_beb++];
return this.element;
};
this.map=function(fn,_bed){
var s=_bed||dj_global;
if(Array.map){
return Array.map(a,fn,s);
}else{
var arr=[];
for(var i=0;i<a.length;i++){
arr.push(fn.call(s,a[i]));
}
return arr;
}
};
this.reset=function(){
_beb=0;
this.element=a[_beb];
};
};
dojo.provide("dojo.collections.Stack");
dojo.collections.Stack=function(arr){
var q=[];
if(arr){
q=q.concat(arr);
}
this.count=q.length;
this.clear=function(){
q=[];
this.count=q.length;
};
this.clone=function(){
return new dojo.collections.Stack(q);
};
this.contains=function(o){
for(var i=0;i<q.length;i++){
if(q[i]==o){
return true;
}
}
return false;
};
this.copyTo=function(arr,i){
arr.splice(i,0,q);
};
this.forEach=function(fn,_bf8){
var s=_bf8||dj_global;
if(Array.forEach){
Array.forEach(q,fn,s);
}else{
for(var i=0;i<q.length;i++){
fn.call(s,q[i],i,q);
}
}
};
this.getIterator=function(){
return new dojo.collections.Iterator(q);
};
this.peek=function(){
return q[(q.length-1)];
};
this.pop=function(){
var r=q.pop();
this.count=q.length;
return r;
};
this.push=function(o){
this.count=q.push(o);
};
this.toArray=function(){
return [].concat(q);
};
};

