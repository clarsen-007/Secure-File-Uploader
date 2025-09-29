<h1>Features:</h1>
<p> - Login / Logout</p>
<p> - Admin: add / delete / change password</p>
<p> - Per-user file upload, list, download, delete ( SFTP-like )</p>
<p> - Flat-file user DB with bcrypt hashes ( username: bcrypt_ash )</p>
<p> - CSRF protection ( token in session )</p>
<p> o- Simple in-memory rate limiting</p>
<p> - Cloudflare-aware real-client IP logging ( CF-Connecting-IP_X-Forwarded-For ) if you use Cloudflare</p>
<p> - HTTPS support ( ssl_conext if CERT_FILE and KEY_FILE exist ); intended to run behind cloudflared, if you use Cloudflare</p>
