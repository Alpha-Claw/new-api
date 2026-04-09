package controller

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// renderOAuth2LoginPage renders an HTML login page for the OAuth authorize flow
func renderOAuth2LoginPage(c *gin.Context, clientId, redirectURI, scope, state string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lumio - 授权登录</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);
      min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e0e0e0}
    .card{background:rgba(255,255,255,.05);backdrop-filter:blur(20px);
      border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:40px;width:400px;
      box-shadow:0 8px 32px rgba(0,0,0,.3)}
    .logo{text-align:center;margin-bottom:24px}
    .logo h1{font-size:22px;font-weight:600}
    .logo p{color:#888;font-size:13px;margin-top:8px}
    .field{margin-bottom:18px}
    .field label{display:block;font-size:13px;color:#aaa;margin-bottom:6px}
    .field input{width:100%%;padding:11px 14px;border-radius:8px;
      border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.08);
      color:#fff;font-size:14px;outline:none;transition:border-color .2s}
    .field input:focus{border-color:#6c63ff}
    .btn{width:100%%;padding:12px;border:none;border-radius:8px;
      background:linear-gradient(135deg,#6c63ff,#4834d4);color:#fff;
      font-size:15px;font-weight:600;cursor:pointer;transition:opacity .2s}
    .btn:hover{opacity:.9}
    .btn:disabled{opacity:.5;cursor:not-allowed}
    .error{color:#ff6b6b;font-size:13px;margin-top:12px;text-align:center;display:none}
    .scope-info{background:rgba(108,99,255,.1);border:1px solid rgba(108,99,255,.2);
      border-radius:8px;padding:12px;margin-bottom:20px;font-size:13px;color:#aaa}
    .scope-info strong{color:#6c63ff}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <h1>🔑 Lumio API</h1>
      <p>应用请求访问你的 Lumio 账户</p>
    </div>
    <div class="scope-info">
      权限范围: <strong>%s</strong>
    </div>
    <div class="field">
      <label>用户名或邮箱</label>
      <input type="text" id="username" placeholder="请输入用户名或邮箱" autofocus>
    </div>
    <div class="field">
      <label>密码</label>
      <input type="password" id="password" placeholder="请输入密码">
    </div>
    <button class="btn" id="btn" onclick="doAuth()">授权并登录</button>
    <div class="error" id="err"></div>
  </div>
  <script>
    document.getElementById('password').addEventListener('keydown',e=>{if(e.key==='Enter')doAuth()});
    async function doAuth(){
      const btn=document.getElementById('btn'),err=document.getElementById('err');
      const username=document.getElementById('username').value.trim();
      const password=document.getElementById('password').value;
      if(!username||!password){err.textContent='请输入用户名和密码';err.style.display='block';return}
      btn.disabled=true;btn.textContent='授权中...';err.style.display='none';
      try{
        const res=await fetch('/api/oauth2/authorize',{
          method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({
            username,password,
            client_id:'%s',redirect_uri:'%s',scope:'%s',state:'%s'
          })
        });
        const data=await res.json();
        if(data.success&&data.redirect_uri){
          window.location.href=data.redirect_uri;
        }else{
          throw new Error(data.message||data.error_description||'授权失败');
        }
      }catch(e){
        err.textContent=e.message;err.style.display='block';
        btn.disabled=false;btn.textContent='授权并登录';
      }
    }
  </script>
</body>
</html>`, scope, clientId, redirectURI, scope, state)

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// renderOAuth2SuccessPage renders a success page after authorization
func renderOAuth2SuccessPage(c *gin.Context) {
	html := `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>授权成功</title>
<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;
min-height:100vh;background:#0f0c29;color:#fff}.ok{text-align:center}
.ok .icon{font-size:64px;margin-bottom:16px}</style></head>
<body><div class="ok"><div class="icon">✅</div><h2>授权成功</h2>
<p style="color:#888">可以关闭此页面，返回终端继续操作。</p></div></body></html>`
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}
