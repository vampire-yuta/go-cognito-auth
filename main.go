package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/gin-gonic/gin"
)

func main() {
	// Cognito User PoolのクライアントID、リージョン、ユーザープールIDを指定
	clientID := os.Getenv("COGNITO_CLIENT_ID")
	userPoolID := os.Getenv("COGNITO_USERPOOL_ID")

	svc := cognitoidentityprovider.New(
		session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		})),
	)

	// Ginフレームワークを初期化
	r := gin.Default()

	// ミドルウェア関数を定義
	authMiddleware := func(c *gin.Context) {
		// Authorizationヘッダからトークンを取得
		authHeader := c.GetHeader("Authorization")
		fmt.Println(authHeader)
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is required"})
			return
		}
		token := authHeader[7:]
		fmt.Println(token)

		// Cognito User Poolにトークンを検証
		params := &cognitoidentityprovider.GetUserInput{
			AccessToken: aws.String(token),
		}
		_, err := svc.GetUser(params)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid access token"})
			return
		}

		// 認証が成功した場合は、次のハンドラに進む
		c.Next()
	}

	// エンドポイントを定義
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	})

	r.GET("/protected", authMiddleware, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "You are authorized to access this resource."})
	})

	// loginエンドポイントを定義
	r.POST("/login", func(c *gin.Context) {
		var reqBody struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.BindJSON(&reqBody); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		fmt.Println(reqBody.Username)
		fmt.Println(reqBody.Password)

		params := &cognitoidentityprovider.AdminInitiateAuthInput{
			AuthFlow: aws.String(cognitoidentityprovider.AuthFlowTypeAdminNoSrpAuth),
			AuthParameters: map[string]*string{
				"USERNAME": aws.String(reqBody.Username),
				"PASSWORD": aws.String(reqBody.Password),
			},
			ClientId:   aws.String(clientID),
			UserPoolId: aws.String(userPoolID),
		}

		res, err := svc.AdminInitiateAuth(params)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
			return
		}
		if res == nil || res.AuthenticationResult == nil || res.AuthenticationResult.IdToken == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Failed to login"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": *res.AuthenticationResult.AccessToken})
	})

	// サーバーを起動
	if err := r.Run(":8080"); err != nil {
		panic(err)
	}
}