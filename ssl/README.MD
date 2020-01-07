密码123456

# 生成一个RSA密钥
> openssl genrsa -des3 -out dev.key 1024
  
# 生成一个证书请求
> openssl req -new -key dev.key -out dev.csr
  
# 自己签发证书
> openssl x509 -req -days 365 -in dev.csr -signkey dev.key -out dev.crt

# 拷贝一个不需要输入密码的密钥文件
> openssl rsa -in dev.key -out dev_nopass.key

生成证书的时候注意：除了下面这些内容其他可以不填，直接回车
注意：Common Name 设置域名
Country Name (2 letter code) [XX]:CN
State or Province Name (full name) []:ShangHai
Locality Name (eg, city) [Default City]:ShangHai
Organization Name (eg, company) [Default Company Ltd]:XSocket
Common Name (eg, your name or your server's hostname) []: *.XSocket.com
Email Address []:xxx@XSocket.com

在 nginx 的 conf 目录下新建 csr 文件夹
把证书复制到 nginx 的 conf/csr 目录下面
server {
    listen 443;
    ssl on;
    ssl_certificate csr/dev.crt;
    ssl_certificate_key csr/dev_nopass.key;
}

windows本地安装证书
右键dev.crt 文件，选择安装证书
把证书安装到“受信任的根证书颁发机构”

