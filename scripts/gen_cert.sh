#!/bin/bash

# TLS 证书生成脚本
# 用于快速生成自签名证书供测试使用

set -e

echo "正在生成 TLS 证书..."

# 生成自签名证书（有效期 365 天）
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"

echo "✅ 证书生成完成！"
echo "  - 证书文件: cert.pem"
echo "  - 私钥文件: key.pem"
echo "  - 有效期: 365 天"
echo ""
echo "注意: 这是自签名证书，仅供测试使用。"
echo "      生产环境建议使用 Let's Encrypt 等正规证书。"
