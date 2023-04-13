# go-cognito-auth

## 使い方

環境変数をセット
```
export AWS_PROFILE=xxxxx
export AWS_DEFAULT_PROFILE=xxxxx
export COGNITO_CLIENT_ID=xxxxx
export COGNITO_USERPOOL_ID=ap-northeast-1_xxxxx
```

サーバー起動

```
go run main.go
```

トークン取得

```
TOKEN=$(curl -X POST -H "Content-Type: application/json" -d '{"username": "testuser-2", "password": "P@ssw0rd01"}' http://localhost:8080/login | jq -r .token)
```

トークン検証

```
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/protected
```

