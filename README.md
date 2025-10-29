## Member Api

該服務展示了使用 PostgreSQL + Redis 實現的會員註冊與登入系統，並且
有加入 Email 二次驗證的機制。

該文件會敘述如何進行使用。

### Swagger UI
https://memberapi.dionysus.pro/swagger-ui/index.html#/

### 複雜流程講解
主要講述多個 API 才能執行的功能，其餘單一 API 服務請參考 Swagger。

#### 註冊流程
1. 呼叫 POST /auth/register
2. 前往 GET /auth/activate 啟用帳號，之所以使用 GET 是因為可以直接提供在 Email 內
這設計違反了 RESTful API 設計原則，最佳實踐會是前端實現一個頁面並且 POST 該 API.
3. 如果沒有收到信，呼叫 POST /auth/resend-activation，有做一定程度的防止濫用，但在該系統中沒有設置冷卻時間。

#### 登入流程
1. 呼叫 POST /auth/login
2. 收到信件的 OTP 呼叫 POST /auth/login/verify
3. 如果沒有收到 OTP，呼叫 POST /auth/otp/resend，十分鐘內不能重複發起。

